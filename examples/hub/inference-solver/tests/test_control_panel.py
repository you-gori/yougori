"""Role, contribution, telemetry and measured-token accounting boundaries."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_service import Flow, PASSWORD
from control_panel import clean, sample


class ControlFlow(Flow):
    def user(self,session):return self.call('/api/session',session=session)[1]['user']

    def test_cached_inventory_does_not_become_a_new_hardware_measurement(self):
        with patch('control_panel.shutil.which',return_value=None):
            stale=sample({'host':{'usedCpuPercent':99},'environments':[{'id':'one','cpuUsage':80}]},False)
        self.assertIsNone(stale['cpu_percent'])
        self.assertIsNone(stale['workloads'][0]['cpu_percent'])

    def test_admin_invites_promotions_and_last_admin_survive_concurrent_demotion(self):
        member=self.member();me=self.user(self.admin);other=self.user(member)
        self.assertEqual(self.call('/api/admin/users/role',{'id':other['id'],'admin':True},member)[0],403)
        self.assertEqual(self.call('/api/admin/users/role',{'id':me['id'],'admin':False},self.admin)[0],400)
        self.assertEqual(self.call('/api/admin/users/role',{'id':other['id'],'admin':True},self.admin)[0],200)
        self.assertTrue(self.user(member)['admin'])
        status,invite,_=self.call('/api/admin/invitations',{'email':'second-admin@example.invalid','admin':True},member)
        self.assertEqual(status,201)
        self.assertEqual(self.call('/api/join',{'email':invite['email'],'password':PASSWORD,'invitation':invite['invitation']})[0],200)
        joined=self.login(invite['email']);joined_id=self.user(joined)['id']
        self.assertTrue(self.user(joined)['admin'])
        self.call('/api/admin/users/role',{'id':joined_id,'admin':False},self.admin)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda pair:self.call('/api/admin/users/role',{'id':pair[1],'admin':False},pair[0])[0],[(self.admin,me['id']),(member,other['id'])]))
        self.assertEqual(sorted(results),[200,400])
        with self.service.store.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM users WHERE admin=1').fetchone()[0],1)

    def test_public_capacity_counts_other_owners_without_exposing_their_sandboxes(self):
        member=self.member();host=self.service.compute.host(self.service.compute.local_host('Shared PC'))
        self.service.grid.inventory(host,{'cpu':4,'memory_gb':8,'slots':2})
        self.call('/api/admin/grid',{'enabled':True,'admission':'open'},self.admin)
        status,created,_=self.call('/api/grid/jobs',{'kind':'launch','request_id':secrets.token_hex(16),'host':host['id'],'cpu':3,'memory_gb':6},self.admin)
        self.assertEqual(status,202,created)
        catalog=self.call('/api/sandboxes')[1];node=catalog['nodes'][0]
        self.assertEqual(node['capacity']['cpu'],4);self.assertEqual(node['capacity']['memory_gb'],8)
        self.assertEqual(node['free'],{'cpu':1,'memory_gb':2,'slots':1})
        self.assertNotIn('vms',catalog)
        own=self.call('/api/grid',session=member)[1];self.assertEqual(own['vms'],[])
        self.assertEqual(own['nodes'][0]['free'],node['free'])
        self.assertEqual(self.call('/api/grid/jobs',{'kind':'launch','request_id':secrets.token_hex(16),'host':host['id'],'cpu':2,'memory_gb':2},member)[0],400)
        self.call('/api/admin/grid',{'enabled':False,'admission':'open'},self.admin)
        self.assertFalse(self.call('/api/sandboxes')[1]['enabled'])

    def test_dashboard_admin_only_presence_history_and_no_secret_inventory(self):
        member=self.member()
        self.assertEqual(self.call('/api/admin/control',session=member)[0],403)
        self.assertEqual(self.call('/api/presence',{},member)[0],200)
        host=self.service.compute.host(self.service.compute.local_host('Telemetry PC'))
        self.service.compute.inventory(host,{'models':[],'telemetry':{'cpu_percent':35,'cpu_cores':4,'memory_used_gb':3,'memory_total_gb':8,
            'token':'never expose','gpus':[{'name':'GPU','temperature_c':65,'memory_used_mb':1234,'memory_total_mb':8192,'utilization_percent':40,'private_key':'no'}]}})
        dashboard=self.call('/api/admin/control',session=self.admin)[1]
        self.assertEqual(dashboard['counts']['online'],1)
        node=dashboard['nodes'][0]
        self.assertEqual(node['samples'][0]['cpu_percent'],35)
        self.assertEqual(node['inventory']['telemetry']['gpus'][0]['temperature_c'],65)
        self.assertNotIn('private_key',str(dashboard));self.assertNotIn('never expose',str(dashboard))
        cleaned=clean({'cpu_percent':float('nan'),'memory_used_gb':-10,'gpus':[{'utilization_percent':101}]})
        self.assertIsNone(cleaned['cpu_percent']);self.assertIsNone(cleaned['memory_used_gb']);self.assertIsNone(cleaned['gpus'][0]['utilization_percent'])

    def test_token_usage_rounding_price_snapshot_and_missing_counts_refund(self):
        self.endpoint();model='test/one';key=self.key()['key'];user=self.service.store.key(key)['user_id']
        with self.service.store.db() as db:db.execute("INSERT INTO credit_ledger VALUES('test-balance',?,1000000,'test',?,NULL,NULL)",(user,int(time.time())))
        self.assertEqual(self.call('/api/admin/prices',{'model':model,'input_usd':'0.25','output_usd':'0.5'},self.admin)[0],200)
        payload=self.completion(model)
        self.assertTrue(self.service.payments.reserve(user,model,'measured',payload))
        self.call('/api/admin/prices',{'model':model,'input_usd':'1','output_usd':'2'},self.admin)
        self.service.payments.finish('measured',True,{'prompt_tokens':3,'completion_tokens':2})
        # Old quote: 3*0.25 + 2*0.5 = 1.75 millionths of a dollar, rounded once.
        self.assertEqual(self.service.payments.snapshot(user)['balance_microusd'],999998)
        self.service.payments.finish('measured',True,{'prompt_tokens':3,'completion_tokens':2})
        self.assertEqual(self.service.payments.snapshot(user)['balance_microusd'],999998)
        self.assertTrue(self.service.payments.reserve(user,model,'missing',self.completion(model)))
        self.service.payments.finish('missing',True,None)
        self.assertEqual(self.service.payments.snapshot(user)['balance_microusd'],999998)
        with self.service.store.db() as db:self.assertEqual(db.execute("SELECT state FROM billing_results WHERE id='missing'").fetchone()[0],'unbilled')


if __name__=='__main__':unittest.main()
