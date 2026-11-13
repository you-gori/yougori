"""Catalog metadata only; these files must never be used for VM execution."""
import hashlib
import json
import os
from pathlib import Path
import harness_download

RAW=b'catalog-only fixture; not a VM image'


def publish_catalog_fixtures(folder):
    """Each harness's own image (for launchers from before the Yougori harness) and the Yougori
    harness's images: one base and every harness's pack, all the same fixture file."""
    root=Path(folder)/'catalog-images'
    digest=hashlib.sha256(RAW).hexdigest()
    specs=harness_download.catalog()
    for name,spec in specs.items():
        destination=root/name;destination.mkdir(parents=True,exist_ok=True)
        if name==harness_download.YOUGORI:
            continue
        (destination/(digest+'.zip')).write_bytes(RAW)
        (destination/'image.json').write_text(json.dumps({'sha256':digest,'bytes':len(RAW),'version':spec['version'],
            'runtime':'yougori-sandbox-vm','platform':'linux/amd64'}))
    destination=root/harness_download.YOUGORI
    (destination/(digest+'.zip')).write_bytes(RAW)
    (destination/(digest+'.tar.gz')).write_bytes(RAW)
    packs={name:{'sha256':digest,'bytes':len(RAW),'version':spec['version'],'base':'base','disk':2,'memory':4}
           for name,spec in specs.items() if name!=harness_download.YOUGORI}
    (destination/'image.json').write_text(json.dumps({'runtime':'yougori-sandbox-vm','platform':'linux/amd64',
        'version':specs[harness_download.YOUGORI]['version'],'bases':{'base':{'sha256':digest,'bytes':len(RAW),'disk':2}},
        'packs':{harness_download.YOUGORI:{'base':'base','disk':2,'memory':4},**packs}}))
    os.environ['SOLVER_VM_IMAGES']=str(root)


def unpublish_catalog_fixtures(folder,names=()):
    """As before the administrator publishes them: these harnesses' images and packs (every
    harness's, and the Yougori harness's images themselves, without names)."""
    root=Path(folder)/'catalog-images'
    listing=root/harness_download.YOUGORI/'image.json'
    for name in names or harness_download.catalog():
        (root/name/'image.json').unlink(missing_ok=True)
    if not names:
        listing.unlink(missing_ok=True)
    elif listing.is_file():
        image=json.loads(listing.read_text())
        image['packs']={name:pack for name,pack in image['packs'].items() if name not in names}
        listing.write_text(json.dumps(image))
