"""Real HTTP, enrollment and ownership boundaries; no paid provider operations."""
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow
from compute_adapter import Adapter, ComputeError
from grid_adapter import GridAdapter
from server import Server


class Infrastructure(Flow):
    def test_model_health_watcher_recovers_from_temporary_storage_error(self):
        attempts=[]
        def refresh():
            attempts.append(True)
            if len(attempts)==1: raise sqlite3.OperationalError('temporary failure')
            self.service.stopped.set()
        with patch.object(self.service,'refresh',side_effect=refresh), patch.object(self.service.stopped,'wait'), patch('builtins.print'):
            self.service.watch()
        self.assertEqual(len(attempts),2)

    def test_second_server_cannot_split_controller_state_on_same_port(self):
        with self.assertRaises(OSError):
            Server(self.web.server_address,self.service)

    def test_unready_runtime_cannot_receive_a_launch(self):
        token,host = self.enroll({'cpu':2,'memory_gb':4,'slots':1,'available':False,'detail':'Update Sandbox VM support.'})
        self.call('/api/admin/grid',{'enabled':True,'admission':'open'},self.admin)
        status,result,_ = self.job(self.admin,kind='launch',host=host['id'],cpu=1,memory_gb=1)
        self.assertEqual(status,400,result)
        self.assertIn('Update Sandbox VM support',str(result))

    def enroll(self, capacity):
        token = secrets.token_urlsafe(32)
        _, pair, _ = self.call('/api/compute/pair/start', {'name':'Grid host','role':'contributor','credential_hash':hashlib.sha256(token.encode()).hexdigest()})
        self.call('/api/compute/pair/approve', {'code':pair['code']}, self.admin)
        host = self.service.compute.host(token)
        status, body, _ = self.call('/api/compute/agent', {'action':'inventory','models':[], 'grid':capacity}, headers={'Authorization':'Bearer '+token})
        self.assertEqual(status,200,body)
        return token,host

    def job(self, user, **payload):
        return self.call('/api/grid/jobs', {'request_id':secrets.token_hex(16),**payload}, user)

    def test_grid_limits_ownership_and_host_bound_results(self):
        member = self.member()
        cap = {'cpu':2,'memory_gb':4,'slots':1}
        token,host = self.enroll(cap)
        self.assertEqual(self.job(self.admin,kind='launch',host=host['id'],cpu=1,memory_gb=1)[0],400)
        self.assertEqual(self.call('/api/admin/grid',{'enabled':True,'admission':'open'},member)[0],403)
        self.assertEqual(self.call('/api/admin/grid',{'enabled':True,'admission':'open'},self.admin)[0],200)
        status,created,_ = self.job(self.admin,kind='launch',host=host['id'],cpu=2,memory_gb=3)
        self.assertEqual(status,202,created)
        self.assertEqual(self.job(self.admin,kind='launch',host=host['id'],cpu=1,memory_gb=1)[0],400)
        job = self.service.grid.poll(host)
        other_token,other = self.enroll(cap)
        self.assertEqual(self.call('/api/compute/agent',{'action':'grid_result','id':job['id'],'ok':True,'result':{}},headers={'Authorization':'Bearer '+other_token})[0],400)
        self.service.grid.result(host,{'id':job['id'],'ok':True,'result':{'sandbox':'exe-'+'a'*32}})
        self.assertEqual(self.job(member,kind='exec',vm=created['vm'],input='id')[0],400)
        self.assertEqual(self.call('/api/grid',session=member)[1]['vms'],[])
        self.assertEqual(self.job(self.admin,kind='exec',vm=created['vm'],input='id')[0],202)
        self.assertEqual(self.job(self.admin,kind='stop',vm=created['vm'])[0],400)

    def test_public_contribution_with_and_without_password(self):
        member = self.member()
        for mode in ('open','password'):
            data = {'enabled':True,'admission':mode,'password':'join-password-for-test'}
            self.assertEqual(self.call('/api/admin/grid',data,self.admin)[0],200)
            token = secrets.token_urlsafe(32)
            _,pair,_ = self.call('/api/compute/pair/start',{'name':'Public node','role':'contributor','credential_hash':hashlib.sha256(token.encode()).hexdigest()})
            if mode == 'password':
                self.assertEqual(self.call('/api/compute/pair/approve',{'code':pair['code'],'password':'wrong'},member)[0],400)
            self.assertEqual(self.call('/api/compute/pair/approve',{'code':pair['code'],'password':data['password'] if mode == 'password' else ''},member)[0],200)

    def test_wallet_admin_only_validation_and_persistence(self):
        data = {'network':'base','address':'0x'+'1'*40}
        self.assertEqual(self.call('/api/admin/wallet',data,self.member())[0],403)
        self.assertEqual(self.call('/api/admin/wallet',{**data,'address':'not-a-wallet'},self.admin)[0],400)
        self.assertEqual(self.call('/api/admin/wallet',data,self.admin)[0],200)
        wallets = self.call('/api/payments',session=self.admin)[1]['wallets']
        self.assertEqual(wallets,[data])
        self.assertEqual(self.call('/api/admin/wallet',{**data,'address':''},self.admin)[1]['wallets'],[])

    def test_grid_adapter_enforces_owner_limits_and_never_relaunches(self):
        adapter = GridAdapter('unused',Path(self.temp.name),{'cpu':2,'memory_gb':4,'slots':1})
        calls = []
        def call(action,**params):
            calls.append((action,params)); return {'sandbox':'exe-'+'a'*32}
        adapter.call = call
        job = {'id':'1'*32,'vm':'a'*32,'kind':'launch','payload':{'cpu':2,'memory_gb':3,'workspace':'C:/secret'}}
        adapter.execute(job); adapter.execute(job)
        self.assertEqual(len(calls),1)
        self.assertNotIn('workspace',calls[0][1])
        self.assertEqual(calls[0][1]['idleSeconds'],0)
        self.assertEqual(calls[0][1]['lifetimeSeconds'],0)
        with self.assertRaises(ValueError):
            adapter.execute({**job,'vm':'b'*32})
        adapter.execute({**job,'kind':'stop','payload':{}})
        adapter.execute({**job,'vm':'b'*32})
        self.assertEqual(len(calls),3)

    def test_grid_inventory_does_not_expire_a_running_vm_after_four_hours(self):
        adapter = GridAdapter('unused',Path(self.temp.name),{'cpu':2,'memory_gb':4,'slots':1})
        vm, sandbox = 'a'*32, 'exe-'+'a'*32
        adapter.vms[vm] = {'sandbox':sandbox,'created':1,'stopped':False}
        calls = []
        def call(action,**params):
            calls.append(action)
            return {'sandboxes':[{'sandbox':sandbox,'state':'running'}]}
        adapter.call = call
        self.assertFalse(adapter.inventory()[vm]['stopped'])
        self.assertEqual(calls,['status'])

    def test_failed_model_start_keeps_catalog_choice(self):
        adapter = Adapter('unused',Path(self.temp.name)/'adapter',True)
        def call(method,**params):
            if method == 'get_platform_state':
                return {'environments':[{'id':'env-one','kind':'container','status':'stopped','description':'Hugging Face · test/one'}]}
            raise ComputeError('CUDA requires update')
        adapter.call = call
        with self.assertRaises(ComputeError): adapter.share('env-one')
        inventory = adapter.inventory()
        self.assertTrue(inventory['models'][0]['shared'])
        self.assertEqual(inventory['models'][0]['state'],'unavailable')

    def test_multi_gpu_quote_is_total_price_and_uses_all_storage(self):
        adapter = Adapter('unused',Path(self.temp.name)/'offers',True)
        seen = []
        def call(method,**params):
            seen.append(params)
            return {'gpus':[{'id':'gpu','name':'Test GPU','vramGb':24,'secureOffer':{'available':True,'price':2.5}}]}
        adapter.call = call
        result = adapter.offers({'gpu_count':8,'disk_gb':100,'storage':'persistent','volume_gb':200})
        self.assertEqual(result['offers'][0]['hourly_usd'],20)
        self.assertEqual(seen,[{'containerDiskGb':300,'gpuCount':8}])


if __name__ == '__main__': unittest.main()
