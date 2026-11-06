"""Settlement boundaries through real HTTP/SQLite, with deterministic RPC evidence.

Never creates a live transfer. Live read-only RPC checks are documented separately.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_service import Flow
from payments import Payments
from payment_chain import ASSETS, TRANSFER, MEMO_PROGRAM, Pending, Rejected, calldata, verify
from chain import base58_encode, base58_decode, transaction

TX = '0x'+'a'*64
BLOCK = '0x'+'b'*64
RECIPIENT = '0x'+'1'*40


def evm_evidence(row):
    receipt = {'transactionHash':row['txid'],'status':'0x1','blockNumber':'0x10','blockHash':BLOCK,
               'logs':[{'address':row['token'],'topics':[TRANSFER,'0x'+'0'*64,'0x'+row['recipient'][2:].zfill(64)],'data':hex(int(row['units']))}]}
    tx = {'hash':row['txid'],'to':row['token'],'input':calldata(row)+row['id'],'value':'0x0','blockHash':BLOCK}
    final = {'number':'0x20'}
    block = {'hash':BLOCK,'timestamp':hex(row['created'])}
    def call(method, params):
        if method == 'eth_chainId': return hex(ASSETS[row['network']]['chain_id'])
        if method == 'eth_getTransactionByHash': return tx
        if method == 'eth_getTransactionReceipt': return receipt
        return final if params[0] == 'finalized' else block
    return call,tx,receipt,final,block


class PaymentFlow(Flow):
    def invoice(self, session=None,network='base'):
        self.assertEqual(self.call('/api/admin/wallet',{'network':network,'address':RECIPIENT},self.admin)[0],200)
        status,invoice,_ = self.call('/api/payments/invoice',{'network':network,'amount':'10'},session or self.admin)
        self.assertEqual(status,200,invoice)
        return invoice

    def row(self, invoice):
        with self.service.store.db() as db:
            return dict(db.execute('SELECT * FROM payment_invoices WHERE id=?',(invoice['id'],)).fetchone())

    def settle_invoice(self,invoice,session=None):
        self.assertEqual(self.call('/api/payments/submit',{'id':invoice['id'],'txid':TX},session or self.admin)[0],200)
        row = self.row(invoice)
        call,*_ = evm_evidence(row)
        with patch('payment_chain.rpc',side_effect=lambda n,m,p:call(m,p)):
            self.service.payments.poll()
        return row

    def test_finalized_transfer_credits_once_even_across_restarts_and_concurrency(self):
        invoice = self.invoice(); row = self.settle_invoice(invoice)
        self.assertEqual(self.call('/api/payments',session=self.admin)[1]['balance_microusd'],10000000)
        # Replaying an already-verified stale work item must not credit twice.
        again = Payments(self.service.store)
        call,*_ = evm_evidence(row)
        with patch('payment_chain.rpc',side_effect=lambda n,m,p:call(m,p)):
            with ThreadPoolExecutor(max_workers=5) as pool:
                list(pool.map(lambda _:again.settle(row),range(5)))
        self.assertEqual(again.snapshot(row['user_id'])['balance_microusd'],10000000)
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='payment'").fetchone()[0],1)
        another = self.invoice()
        self.assertEqual(self.call('/api/payments/submit',{'id':another['id'],'txid':TX},self.admin)[0],400)

    def test_owner_binding_and_wallet_changes_preserve_invoice(self):
        member = self.member(); invoice = self.invoice()
        self.assertEqual(self.call('/api/payments',session=member)[1]['invoices'],[])
        self.assertEqual(self.call('/api/payments/submit',{'id':invoice['id'],'txid':TX},member)[0],400)
        self.assertEqual(self.call('/api/payments/cancel',{'id':invoice['id']},member)[0],400)
        self.call('/api/admin/wallet',{'network':'base','address':'0x'+'2'*40},self.admin)
        self.assertEqual(self.row(invoice)['recipient'],RECIPIENT)
        self.settle_invoice(invoice)
        self.assertEqual(self.call('/api/payments',session=self.admin)[1]['balance_microusd'],10000000)

    def test_all_evm_networks_require_correct_chain_token_amount_reference_and_finality(self):
        for network,asset in ASSETS.items():
            if not asset.get('chain_id'): continue
            row = {'network':network,'token':asset['token'],'recipient':RECIPIENT,'id':'f'*64,
                   'units':str(10*10**asset['decimals']),'created':int(time.time()),'txid':TX}
            call,tx,receipt,final,block = evm_evidence(row)
            self.assertEqual(verify(row,call)['block'],16)
            for label, mutate,exception in [
                ('token',lambda t,r,f,b:t.update(to='0x'+'3'*40),Rejected),
                ('reference',lambda t,r,f,b:t.update(input=calldata(row)+'e'*64),Rejected),
                ('amount',lambda t,r,f,b:r['logs'][0].update(data='0x1'),Rejected),
                ('recipient',lambda t,r,f,b:r['logs'][0]['topics'].__setitem__(2,'0x'+'0'*64),Rejected),
                ('receipt token',lambda t,r,f,b:r['logs'][0].update(address='0x'+'5'*40),Rejected),
                ('failed',lambda t,r,f,b:r.update(status='0x0'),Rejected),
                ('unfinalized',lambda t,r,f,b:f.update(number='0x1'),Pending),
                ('reorg',lambda t,r,f,b:b.update(hash='0x'+'d'*64),Pending),
                ('old',lambda t,r,f,b:b.update(timestamp='0x1'),Rejected),
            ]:
                with self.subTest(network=network,case=label):
                    call,tx,receipt,final,block = evm_evidence(row); mutate(tx,receipt,final,block)
                    with self.assertRaises(exception): verify(row,call)
            with self.assertRaises(Pending): verify(row,lambda m,p:'0x999' if m=='eth_chainId' else call(m,p))

    def test_pending_retries_and_stale_verification_cannot_settle_replaced_transaction(self):
        invoice = self.invoice()
        self.call('/api/payments/submit',{'id':invoice['id'],'txid':TX},self.admin)
        old = self.row(invoice)
        with patch('payments.verify',side_effect=Pending('Waiting for finality.')): self.service.payments.poll()
        self.assertEqual(self.row(invoice)['state'],'pending')
        self.assertEqual(self.call('/api/payments',session=self.admin)[1]['balance_microusd'],0)
        self.call('/api/payments/submit',{'id':invoice['id'],'txid':'0x'+'c'*64},self.admin)
        call,*_ = evm_evidence(old)
        with patch('payment_chain.rpc',side_effect=lambda n,m,p:call(m,p)): self.service.payments.settle(old)
        self.assertEqual(self.row(invoice)['state'],'pending')
        self.assertEqual(self.call('/api/payments',session=self.admin)[1]['balance_microusd'],0)

    def test_atomic_credits_real_inference_and_failed_request_refund(self):
        member = self.member(); self.settle_invoice(self.invoice(member),member)
        self.endpoint(); model = 'test/one'; key = self.key(session=member)['key']
        self.assertEqual(self.call('/api/admin/prices',{'model':model,'input_usd':'1','output_usd':'2'},member)[0],403)
        self.assertEqual(self.call('/api/admin/prices',{'model':model,'input_usd':'1','output_usd':'2'},self.admin)[0],200)
        failed = self.call('/v1/chat/completions',self.completion(model,content='fail'),key=key)
        self.assertEqual(failed[0],502)
        self.assertEqual(self.call('/api/payments',session=member)[1]['balance_microusd'],10000000)
        result=self.call('/v1/chat/completions',self.completion(model),key=key)
        self.assertEqual(result[0],200)
        # Fixture reports 3 input and 2 output tokens: $0.000003 + $0.000004.
        self.assertEqual(self.call('/api/payments',session=member)[1]['balance_microusd'],9999993)
        usage=self.call('/api/usage',session=member)[1]['requests']
        self.assertTrue(any(r['cost_microusd']==7 for r in usage))
        user=self.service.store.key(key)['user_id'];payload=self.completion(model)
        with self.service.store.db() as db:
            db.execute("INSERT INTO credit_ledger VALUES('adjust',?,?,'test',?,NULL,NULL)",(user,-9990000,int(time.time())))
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(lambda i:self.service.payments.reserve(user,model,str(i),dict(payload)),range(2)))
        self.assertEqual(sorted(outcomes),[False,True])

    def test_pending_rows_resume_in_fresh_payments_instance(self):
        invoice = self.invoice(); self.call('/api/payments/submit',{'id':invoice['id'],'txid':TX},self.admin)
        row = self.row(invoice); call,*_ = evm_evidence(row)
        with patch('payment_chain.rpc',side_effect=lambda n,m,p:call(m,p)):
            Payments(self.service.store).poll()
        self.assertEqual(self.row(invoice)['state'],'settled')

    def test_input_limits_and_cancelled_invoice_can_recover_a_late_real_payment(self):
        for amount in (True,10,'NaN','1e3','1.0000001','-1','0','1001'):
            self.assertEqual(self.call('/api/payments/invoice',{'network':'base','amount':amount},self.admin)[0],400)
        invoice = self.invoice()
        self.assertEqual(self.call('/api/payments/cancel',{'id':invoice['id']},self.admin)[0],200)
        self.settle_invoice(invoice)
        self.assertEqual(self.row(invoice)['state'],'settled')


class OtherChains(unittest.TestCase):
    def test_solana_finalized_memo_and_actual_recipient_balance(self):
        self.assertIsNone(transaction('solana','2'*100000))
        row = {'network':'solana','id':'f'*64,'recipient':base58_encode(bytes([1])*32),'token':ASSETS['solana']['token'],
               'created':100,'units':'1000000','txid':base58_encode(bytes([2])*64)}
        balance = {'accountIndex':1,'owner':row['recipient'],'mint':row['token'],'uiTokenAmount':{'decimals':6,'amount':'1000000'}}
        result = {'slot':50,'blockTime':101,'transaction':{'signatures':[row['txid']],'message':{'instructions':[{'programId':MEMO_PROGRAM,'parsed':'solver:'+row['id']}]}},
                  'meta':{'err':None,'preTokenBalances':[],'postTokenBalances':[balance]}}
        calls=[]
        def call(m,p):
            calls.append((m,p))
            return '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d' if m=='getGenesisHash' else result
        self.assertEqual(verify(row,call),{'slot':50})
        self.assertEqual(calls[-1][1][1]['commitment'],'finalized')
        for field,value in [('mint',base58_encode(bytes(32))),('owner',base58_encode(bytes(32)))]:
            before=balance[field]; balance[field]=value
            with self.assertRaises(Rejected):verify(row,call)
            balance[field]=before
        result['transaction']['message']['instructions'][0]['parsed']='wrong'
        with self.assertRaises(Rejected):verify(row,call)
        result['transaction']['message']['instructions'][0]['parsed']='solver:'+row['id']
        result['meta']['err']={'InstructionError':[0,'failed']}
        with self.assertRaises(Rejected):verify(row,call)

    def test_tron_solidified_receipt_memo_token_and_transfer(self):
        row = {'network':'tron','id':'f'*64,'recipient':ASSETS['tron']['token'],'token':ASSETS['tron']['token'],'created':100,'units':'1000000','txid':'a'*64}
        token=base58_decode(row['token'])[1:21].hex()
        tx={'txID':row['txid'],'raw_data':{'data':('solver:'+row['id']).encode().hex(),'contract':[{'type':'TriggerSmartContract','parameter':{'value':{'contract_address':'41'+token,'data':calldata(row)[2:]}}}]}}
        receipt={'id':row['txid'],'receipt':{'result':'SUCCESS'},'blockNumber':20,'blockTimeStamp':101000,'log':[{'address':token,'topics':[TRANSFER[2:],'0'*64,token.zfill(64)],'data':hex(1000000)[2:]}]}
        def call(m,p):
            return {'blockID':'00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc'} if m=='getblockbynum' else tx if m=='gettransactionbyid' else receipt
        self.assertEqual(verify(row,call),{'block':20})
        receipt['receipt']['result']='REVERT'
        with self.assertRaises(Rejected):verify(row,call)
        receipt['receipt']['result']='SUCCESS'; tx['raw_data']['data']='77726f6e67'
        with self.assertRaises(Rejected):verify(row,call)


if __name__ == '__main__':unittest.main()
