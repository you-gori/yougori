"""Catalog metadata only; these files must never be used for VM execution."""
import hashlib
import json
import os
from pathlib import Path
import harness_download

def publish_catalog_fixtures(folder):
    root=Path(folder)/'catalog-images'
    raw=b'catalog-only fixture; not a VM image'
    digest=hashlib.sha256(raw).hexdigest()
    for name,spec in harness_download.catalog().items():
        destination=root/name;destination.mkdir(parents=True,exist_ok=True)
        (destination/(digest+'.zip')).write_bytes(raw)
        (destination/'image.json').write_text(json.dumps({'sha256':digest,'bytes':len(raw),'version':spec['version'],
            'runtime':'yougori-sandbox-vm','platform':'linux/amd64'}))
    os.environ['SOLVER_VM_IMAGES']=str(root)
