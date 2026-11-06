"""Opt-in read-only mainnet checks. Never signs or broadcasts a transaction."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'site'))
from payment_chain import ASSETS, TRANSFER, Pending, calldata, rpc


def probe(network):
    asset = ASSETS[network]
    if network == 'solana':
        genesis = rpc(network,'getGenesisHash',[])
        assert genesis == '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'
        token = rpc(network,'getAccountInfo',[asset['token'],{'encoding':'jsonParsed','commitment':'finalized'}])['value']
        assert token['data']['parsed']['info']['decimals'] == 6
        return {'genesis':genesis,'token_decimals':6,'finalized_slot':rpc(network,'getSlot',[{'commitment':'finalized'}])}
    if network == 'tron':
        genesis = rpc(network,'getblockbynum',{'num':0})['blockID']
        assert genesis == '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc'
        solid = rpc(network,'getnowblock',{})
        return {'genesis':genesis,'solidified_block':solid['block_header']['raw_data']['number']}
    chain = int(rpc(network,'eth_chainId',[]),16)
    assert chain == asset['chain_id']
    decimals = int(rpc(network,'eth_call',[{'to':asset['token'],'data':'0x313ce567'},'latest']),16)
    assert decimals == asset['decimals']
    final = rpc(network,'eth_getBlockByNumber',['finalized',False])
    head = int(rpc(network,'eth_blockNumber',[]),16)
    logs = rpc(network,'eth_getLogs',[{'address':asset['token'],'fromBlock':hex(head-15),'toBlock':hex(head-10),'topics':[TRANSFER]}])
    # Simulate a one-unit self-transfer from an existing holder, with invoice data.
    # eth_call is read-only: it neither signs nor changes chain state.
    matched = False
    for log in reversed(logs[-20:]):
        recipient = '0x'+log['topics'][2][-40:]
        if recipient == '0x'+'0'*40: continue
        row={'recipient':recipient,'units':'1','network':network}
        try:
            result=rpc(network,'eth_call',[{'from':recipient,'to':asset['token'],'data':calldata(row)+'f'*64,'gas':'0x30d40'},'latest'])
            if int(result,16)==1:
                matched=True; break
        except (ValueError,Pending):
            # A recent recipient may already have transferred its balance away.
            continue
    return {'chain_id':chain,'token_decimals':decimals,'finalized_block':int(final['number'],16),'invoice_calldata_simulated':matched}


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True); args=parser.parse_args()
    def run(network):
        try:return network,{'ok':True,**probe(network)}
        except Exception as error:return network,{'ok':False,'error':str(error)}
    with ThreadPoolExecutor(max_workers=7) as pool: results=dict(pool.map(run,ASSETS))
    data={'at':int(time.time()),'read_only':True,'networks':results}
    args.output.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(data,indent=2))
    return 0 if all(v['ok'] for v in results.values()) else 1


if __name__=='__main__':raise SystemExit(main())
