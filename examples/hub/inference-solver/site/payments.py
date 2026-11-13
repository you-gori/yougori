"""Noncustodial invoices and atomic, exactly-once credit accounting."""
import json
import re
import secrets
import sqlite3
import threading
import time
from chain import address, evm_address, transaction
from payment_chain import ASSETS, Pending, Rejected, payment_data, verify
from subscriptions import Subscriptions

NETWORKS = {"ethereum": "Ethereum", "base": "Base", "arbitrum": "Arbitrum", "polygon": "Polygon", "bsc": "BNB Smart Chain", "solana": "Solana", "tron": "Tron"}


class WalletInput(ValueError):
    """Safe wallet input errors, without provider or private-key details."""


class Payments:
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        with store.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS payment_wallets(network TEXT PRIMARY KEY,address TEXT NOT NULL)")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS payment_invoices (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), network TEXT NOT NULL,
                    token TEXT NOT NULL, recipient TEXT NOT NULL, units TEXT NOT NULL, credits INTEGER NOT NULL,
                    created INTEGER NOT NULL, txid TEXT, state TEXT NOT NULL DEFAULT 'created',
                    detail TEXT NOT NULL DEFAULT '', checked INTEGER NOT NULL DEFAULT 0, evidence TEXT NOT NULL DEFAULT '{}');
                CREATE INDEX IF NOT EXISTS payment_pending ON payment_invoices(state,checked);
                CREATE TABLE IF NOT EXISTS credit_ledger (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), amount INTEGER NOT NULL,
                    kind TEXT NOT NULL, at INTEGER NOT NULL, network TEXT, txid TEXT, UNIQUE(network,txid));
                CREATE INDEX IF NOT EXISTS credit_owner ON credit_ledger(user_id);
                CREATE TABLE IF NOT EXISTS token_prices (model TEXT PRIMARY KEY, input_microusd INTEGER NOT NULL, output_microusd INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS token_quotes (id TEXT PRIMARY KEY, input_rate INTEGER NOT NULL, output_rate INTEGER NOT NULL, input_ceiling INTEGER NOT NULL, output_ceiling INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS token_cache_prices (model TEXT PRIMARY KEY, cached_microusd INTEGER NOT NULL);
                -- The cached-input rate in force when a request was reserved.
                CREATE TABLE IF NOT EXISTS token_quote_cache (id TEXT PRIMARY KEY, cached_rate INTEGER NOT NULL);
                -- A media model's prices per image and per second of video or audio, and the most a job may
                -- be charged for at the rates in force when it was reserved.
                CREATE TABLE IF NOT EXISTS media_prices (model TEXT PRIMARY KEY, image_microusd INTEGER NOT NULL, second_microusd INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS media_quotes (id TEXT PRIMARY KEY, image_rate INTEGER NOT NULL, second_rate INTEGER NOT NULL, image_ceiling INTEGER NOT NULL, ms_ceiling INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS billing_results (id TEXT PRIMARY KEY, state TEXT NOT NULL, charged INTEGER NOT NULL, detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS credit_holds (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                    amount INTEGER NOT NULL, expires INTEGER NOT NULL);
            """)
        self.subscriptions = Subscriptions(store)

    def snapshot(self, user=None):
        with self.store.db() as db:
            wallets = [dict(r) for r in db.execute("SELECT network,address FROM payment_wallets ORDER BY network")]
            cached = {r['model']: r['cached_microusd'] for r in db.execute('SELECT * FROM token_cache_prices')}
            prices = {r['model']: {'input_microusd_per_million':r['input_microusd'],'output_microusd_per_million':r['output_microusd'],
                                   'cached_microusd_per_million':cached.get(r['model'],r['input_microusd'])} for r in db.execute('SELECT * FROM token_prices')}
            media_prices = {r['model']: {'image_microusd': r['image_microusd'], 'second_microusd': r['second_microusd']} for r in db.execute('SELECT * FROM media_prices')}
            invoices = [dict(r) for r in db.execute("SELECT * FROM payment_invoices WHERE user_id=? ORDER BY created DESC,id DESC LIMIT 50", (user,))] if user else []
            balance = self.balance(db,user) if user else 0
        return {"networks": NETWORKS, "wallets": wallets, "settlement": "automatic", "balance_microusd": balance,
                "prices": prices, "media_prices": media_prices, "invoices": [self.public(r) for r in invoices],
                "assets": {n:{k:v for k,v in a.items() if k != 'rpc'} for n,a in ASSETS.items()}}

    @staticmethod
    def balance(db, user):
        earned = db.execute('SELECT COALESCE(SUM(amount),0) FROM credit_ledger WHERE user_id=?',(user,)).fetchone()[0]
        held = db.execute('SELECT COALESCE(SUM(amount),0) FROM credit_holds WHERE user_id=? AND expires>?',(user,int(time.time()))).fetchone()[0]
        return earned-held

    @staticmethod
    def public(row):
        return {**{k:v for k,v in row.items() if k not in ('user_id','evidence')}, **payment_data(row)}

    @staticmethod
    def amount(value, minimum=1, maximum=1000):
        # Strings only: never round a float or accept exponent/NaN.
        if not isinstance(value,str) or not re.fullmatch(r'(0|[1-9][0-9]{0,4})(\.[0-9]{1,6})?',value):
            raise WalletInput('Enter an amount with up to six decimal places.')
        whole, _, fraction = value.partition('.')
        amount = int(whole)*1000000 + int(fraction.ljust(6,'0'))
        if not minimum*1000000 <= amount <= maximum*1000000:
            raise WalletInput(f'Choose an amount from {minimum} to {maximum}.')
        return amount

    def create(self, user, data):
        network = data.get('network')
        if network not in ASSETS:
            raise WalletInput('Choose a supported payment network.')
        credits = self.amount(data.get('amount'))
        asset = ASSETS[network]
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            wallet = db.execute('SELECT address FROM payment_wallets WHERE network=?',(network,)).fetchone()
            if not wallet:
                raise WalletInput('The administrator has not connected a receiving wallet on this network.')
            if db.execute("SELECT COUNT(*) FROM payment_invoices WHERE user_id=? AND state IN ('created','pending')",(user,)).fetchone()[0] >= 10:
                raise WalletInput('Finish or cancel an unused invoice before creating another.')
            identity = secrets.token_hex(32)
            db.execute('INSERT INTO payment_invoices(id,user_id,network,token,recipient,units,credits,created) VALUES(?,?,?,?,?,?,?,?)',
                       (identity,user,network,asset['token'],wallet['address'],str(credits*10**(asset['decimals']-6)),credits,int(time.time())))
            row = dict(db.execute('SELECT * FROM payment_invoices WHERE id=?',(identity,)).fetchone())
        return self.public(row)

    def submit(self, user, data):
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM payment_invoices WHERE id=? AND user_id=?',(data.get('id'),user)).fetchone()
            if not row:
                raise WalletInput('Invoice not found.')
            if row['state'] == 'settled':
                return self.public(dict(row))
            txid = transaction(row['network'],data.get('txid'))
            if not txid:
                raise WalletInput('Enter a valid transaction ID for this network.')
            if db.execute('SELECT 1 FROM credit_ledger WHERE network=? AND txid=?',(row['network'],txid)).fetchone():
                raise WalletInput('This transaction has already been credited.')
            db.execute("UPDATE payment_invoices SET txid=?,state='pending',detail='Waiting for chain verification.',checked=0 WHERE id=?",(txid,row['id']))
            row = dict(db.execute('SELECT * FROM payment_invoices WHERE id=?',(row['id'],)).fetchone())
        return self.public(row)

    def cancel(self,user,data):
        with self.store.db() as db:
            changed = db.execute("UPDATE payment_invoices SET state='cancelled' WHERE id=? AND user_id=? AND state='created' AND txid IS NULL",(data.get('id'),user)).rowcount
            if not changed:
                raise WalletInput('Only unused invoices can be cancelled. Submitted payments keep being verified.')
        return {'ok':True}

    def settle(self, row):
        """Network I/O outside the transaction; recheck the exact claim under write lock."""
        evidence = None
        try:
            evidence = verify(row)
            state,detail = 'settled','Finalized on-chain. Credits added.'
        except Pending as error:
            state,detail = 'pending',str(error)
        except Rejected as error:
            state,detail = 'rejected',str(error)
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT state,txid FROM payment_invoices WHERE id=?',(row['id'],)).fetchone()
            if not current or current['state'] != 'pending' or current['txid'] != row['txid']:
                return
            if evidence is not None:
                existing = db.execute('SELECT id FROM credit_ledger WHERE network=? AND txid=?',(row['network'],row['txid'])).fetchone()
                if existing and existing['id'] != row['id']:
                    state,detail = 'rejected','This transaction has already been credited.'
                else:
                    db.execute('INSERT OR IGNORE INTO credit_ledger VALUES(?,?,?,?,?,?,?)',(row['id'],row['user_id'],row['credits'],'payment',int(time.time()),row['network'],row['txid']))
                    self.store.audit(db,row['user_id'],'payment.settled',row['id'])
            db.execute('UPDATE payment_invoices SET state=?,detail=?,checked=?,evidence=? WHERE id=?',
                       (state,detail,int(time.time()),json.dumps(evidence or {}),row['id']))

    def poll(self, stopped=None):
        if not self.lock.acquire(blocking=False):
            return
        try:
            with self.store.db() as db:
                rows = [dict(r) for r in db.execute("SELECT * FROM payment_invoices WHERE state='pending' AND checked<? ORDER BY checked,created LIMIT 8",(int(time.time())-20,))]
            for row in rows:
                if stopped and stopped.is_set():
                    break
                self.settle(row)
        finally:
            self.lock.release()

    def watch(self, stopped):
        while not stopped.is_set():
            try:
                self.poll(stopped)
            except (sqlite3.Error,OSError):
                pass  # Durable pending rows are retried, never credited on transport failure.
            stopped.wait(5)

    def price(self,actor,data):
        input_rate = self.amount(data.get('input_usd'),0,1000)
        output_rate = self.amount(data.get('output_usd'),0,1000)
        # Cached input: prompt tokens the model server reused from its cache. Without a price of
        # its own, it costs the input price.
        cached_rate = None if data.get('cached_usd') in (None,'') else self.amount(data.get('cached_usd'),0,1000)
        if cached_rate is not None and cached_rate > input_rate:
            raise WalletInput('Cached input cannot cost more than input.')
        with self.store.db() as db:
            if not db.execute('SELECT 1 FROM models WHERE upstream=?',(data.get('model'),)).fetchone():
                raise WalletInput('Choose an available model.')
            db.execute('INSERT INTO token_prices VALUES(?,?,?) ON CONFLICT(model) DO UPDATE SET input_microusd=excluded.input_microusd,output_microusd=excluded.output_microusd',(data['model'],input_rate,output_rate))
            if cached_rate is None:
                db.execute('DELETE FROM token_cache_prices WHERE model=?',(data['model'],))
            else:
                db.execute('INSERT INTO token_cache_prices VALUES(?,?) ON CONFLICT(model) DO UPDATE SET cached_microusd=excluded.cached_microusd',(data['model'],cached_rate))
            self.store.audit(db,actor,'model.token_price',data['model'])
        return {'ok':True}

    def media_price(self, actor, data):
        """A media model's prices: dollars per image, and per second of video or audio made."""
        image_rate = self.amount(data.get('image_usd'), 0, 1000)
        second_rate = self.amount(data.get('second_usd'), 0, 1000)
        with self.store.db() as db:
            if not db.execute('SELECT 1 FROM models WHERE upstream=?', (data.get('model'),)).fetchone():
                raise WalletInput('Choose an available model.')
            db.execute('INSERT INTO media_prices VALUES(?,?,?) ON CONFLICT(model) DO UPDATE SET image_microusd=excluded.image_microusd,second_microusd=excluded.second_microusd',
                       (data['model'], image_rate, second_rate))
            self.store.audit(db, actor, 'model.media_price', data['model'])
        return {'ok': True}

    @staticmethod
    def media_cost(images, output_ms, image_rate, second_rate):
        """Microdollars for one job, rounded up: its images, and its seconds of video or audio."""
        return images * image_rate + (output_ms * second_rate + 999) // 1000

    def reserve_media(self, user, model, request, job, task):
        """Holds the most a job may cost: its image count, or the seconds it asks for (a video or
        sound job without a length: a minute; a speech job: a second per ten characters, five at
        least). Only what the model server measured is billed when the job ends."""
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            price = db.execute('SELECT * FROM media_prices WHERE model=?', (model,)).fetchone()
            if not price or not (price['image_microusd'] or price['second_microusd']):
                return True
            count = job.get('count') if type(job.get('count')) is int else 1
            images = max(1, min(8, count)) if task in ('text-to-image', 'image-to-image') else 0
            if task == 'text-to-speech':
                text = job.get('text') if isinstance(job.get('text'), str) else job.get('prompt') if isinstance(job.get('prompt'), str) else ''
                seconds = max(5, -(-len(text) // 10))
            elif task in ('text-to-video', 'image-to-video', 'text-to-audio'):
                asked = job.get('seconds')
                seconds = max(1, min(61, int(asked) + 1)) if isinstance(asked, (int, float)) and not isinstance(asked, bool) and asked == asked else 60
            else:
                seconds = 0
            cost = self.media_cost(images, seconds * 1000, price['image_microusd'], price['second_microusd'])
            if self.balance(db, user) < cost:
                return False
            # A job may wait in a queue and run for half an hour: the hold lasts two hours.
            db.execute('INSERT INTO credit_holds VALUES(?,?,?,?)', (request, user, cost, int(time.time()) + 7200))
            db.execute('INSERT INTO media_quotes VALUES(?,?,?,?,?)', (request, price['image_microusd'], price['second_microusd'], images, seconds * 1000))
        return True

    def finish_media(self, request, completed, usage, record=None):
        """Charges one job by what it made (`usage`: images and output_ms, as the model server
        measured them), within its reservation; a job that did not complete is not charged."""
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            hold = db.execute('SELECT * FROM credit_holds WHERE id=?', (request,)).fetchone()
            quote = db.execute('SELECT * FROM media_quotes WHERE id=?', (request,)).fetchone()
            state, charge, detail = 'free', 0, ''
            if hold and quote:
                counts = [usage.get(k) for k in ('images', 'output_ms')] if isinstance(usage, dict) else [None, None]
                valid = all(type(n) is int and n >= 0 for n in counts)
                if not completed:
                    state, detail = 'refunded', 'Job did not complete.'
                elif hold['expires'] <= time.time():
                    state, detail = 'unbilled', 'The reservation expired.'
                elif not valid or counts[0] > quote['image_ceiling'] or counts[1] > quote['ms_ceiling']:
                    state, detail = 'unbilled', 'Model server omitted valid usage or exceeded the reserved output.'
                else:
                    charge = self.media_cost(counts[0], counts[1], quote['image_rate'], quote['second_rate'])
                    if charge > hold['amount']:
                        raise ValueError('Measured price exceeded the reservation.')
                    state = 'charged'
                    db.execute('INSERT OR IGNORE INTO credit_ledger VALUES(?,?,?,?,?,NULL,NULL)', (request, hold['user_id'], -charge, 'inference', int(time.time())))
            db.execute('INSERT OR IGNORE INTO billing_results VALUES(?,?,?,?)', (request, state, charge, detail))
            db.execute('DELETE FROM credit_holds WHERE id=?', (request,))
            db.execute('DELETE FROM media_quotes WHERE id=?', (request,))
            if record:
                record(db)

    @staticmethod
    def cost(input_tokens,output_tokens,input_rate,output_rate,cached_tokens=0,cached_rate=0):
        """Microdollars for one request, rounded up. Cached tokens are part of the input tokens."""
        return ((input_tokens-cached_tokens)*input_rate+cached_tokens*cached_rate+output_tokens*output_rate+999999)//1000000

    def reserve(self,user,model,request,payload):
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            price = db.execute('SELECT * FROM token_prices WHERE model=?',(model,)).fetchone()
            if not price or not (price['input_microusd'] or price['output_microusd']):
                return True
            # A subscription with tokens left in its window includes the request: nothing is held,
            # and its measured tokens count in the window when it finishes.
            if self.subscriptions.cover(db, user, model, request, int(time.time())):
                return True
            cached = db.execute('SELECT cached_microusd FROM token_cache_prices WHERE model=?',(model,)).fetchone()
            # This is a conservative financial ceiling, NOT a token count. Only
            # measured upstream usage is ever billed; exceeding it is not charged.
            size=len(json.dumps(payload,ensure_ascii=False).encode('utf-8'))
            inputs=8*size+256*(len(payload.get('messages',[]))+1)+4096
            outputs=payload.get('max_completion_tokens',payload.get('max_tokens',1024))
            cost=self.cost(inputs,outputs,price['input_microusd'],price['output_microusd'])
            if self.balance(db,user) < cost:
                return False
            db.execute('INSERT INTO credit_holds VALUES(?,?,?,?)',(request,user,cost,int(time.time())+600))
            db.execute('INSERT INTO token_quotes VALUES(?,?,?,?,?)',(request,price['input_microusd'],price['output_microusd'],inputs,outputs))
            db.execute('INSERT INTO token_quote_cache VALUES(?,?)',(request,cached['cached_microusd'] if cached else price['input_microusd']))
            if 'max_completion_tokens' in payload:
                payload.pop('max_tokens',None)
                payload['max_completion_tokens']=outputs
            else:
                payload['max_tokens']=outputs
        return True

    def refusal(self, user, model):
        """Why a priced request could not start: a used-up subscription window, or a balance below the hold."""
        with self.store.db() as db:
            resets = self.subscriptions.used_up(db, user, model, int(time.time()))
        if resets:
            return ("Your subscription's limit for this window is reached. It resets at "
                    + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(resets))
                    + "; until then requests are charged from your balance, which is below the temporary request reservation. Top up in Usage.")
        return 'Balance is below the temporary request reservation. Top up in Usage or lower the output token limit.'

    def finish(self,request,completed,usage,record=None,cached=None):
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            hold = db.execute('SELECT * FROM credit_holds WHERE id=?',(request,)).fetchone()
            quote = db.execute('SELECT * FROM token_quotes WHERE id=?',(request,)).fetchone()
            cached_quote = db.execute('SELECT cached_rate FROM token_quote_cache WHERE id=?',(request,)).fetchone()
            state,charge,detail='free',0,''
            measured=[usage.get(k) for k in ('prompt_tokens','completion_tokens')] if isinstance(usage,dict) else [None,None]
            counted=sum(measured) if completed and all(type(n) is int and n>=0 for n in measured) else 0
            if self.subscriptions.settle(db,request,counted):
                state,detail='subscription','Included in the subscription.'
            if hold and quote:
                counts=[usage.get(k) for k in ('prompt_tokens','completion_tokens')] if isinstance(usage,dict) else [None,None]
                valid=all(type(n) is int and n>=0 for n in counts)
                # Cached tokens the model server did not report validly are billed as ordinary input.
                reused=cached if valid and type(cached) is int and 0<=cached<=counts[0] else 0
                if not completed:
                    state,detail='refunded','Request did not complete.'
                elif hold['expires'] <= time.time():
                    state,detail='unbilled','The reservation expired.'
                elif not valid or counts[0]>quote['input_ceiling'] or counts[1]>quote['output_ceiling']:
                    state,detail='unbilled','Model server omitted valid usage or exceeded the reserved token ceiling.'
                else:
                    charge=self.cost(*counts,quote['input_rate'],quote['output_rate'],reused,
                                     cached_quote['cached_rate'] if cached_quote else quote['input_rate'])
                    if charge>hold['amount']:
                        raise ValueError('Measured price exceeded the reservation.')
                    state='charged'
                    db.execute('INSERT OR IGNORE INTO credit_ledger VALUES(?,?,?,?,?,NULL,NULL)',(request,hold['user_id'],-charge,'inference',int(time.time())))
            db.execute('INSERT OR IGNORE INTO billing_results VALUES(?,?,?,?)',(request,state,charge,detail))
            db.execute('DELETE FROM credit_holds WHERE id=?',(request,))
            db.execute('DELETE FROM token_quotes WHERE id=?',(request,))
            db.execute('DELETE FROM token_quote_cache WHERE id=?',(request,))
            if record:
                record(db)

    def save(self, actor, data):
        network, wallet = data.get("network"), data.get("address")
        if network not in NETWORKS or not isinstance(wallet, str):
            raise WalletInput("Choose a payment network and its public receiving address.")
        wallet = wallet.strip()
        if wallet and not (evm_address(wallet) if network == "base" else address(network, wallet)):
            raise WalletInput("This wallet address is invalid for the selected network.")
        if wallet and wallet.lower() == "0x" + "0" * 40:
            raise WalletInput("The zero address cannot receive your payments.")
        with self.store.db() as db:
            if wallet:
                db.execute("INSERT INTO payment_wallets VALUES(?,?) ON CONFLICT(network) DO UPDATE SET address=excluded.address", (network,wallet))
            else:
                db.execute("DELETE FROM payment_wallets WHERE network=?", (network,))
            self.store.audit(db,actor,"wallet.updated",network)
        return self.snapshot()
