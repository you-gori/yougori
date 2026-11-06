"""A CLI source profile alone must not advertise a ready VM installation."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'site'))
import harness_download

class Availability(unittest.TestCase):
    def test_complete_current_artifacts_are_required(self):
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'SOLVER_VM_IMAGES':folder}):
            self.assertFalse(harness_download.availability('shannon')['available'])
            root=Path(folder)/'shannon';root.mkdir()
            spec={'sha256':'a'*64,'bytes':7,'version':harness_download.catalog()['shannon']['version'],
                  'runtime':'yougori-sandbox-vm','platform':'linux/amd64'}
            record=root/'image.json';record.write_text(json.dumps(spec))
            self.assertFalse(harness_download.availability('shannon')['available'])
            (root/('a'*64+'.zip')).write_bytes(b'fixture')
            self.assertTrue(harness_download.availability('shannon')['available'])
            record.write_text(json.dumps({**spec,'version':'old'}))
            self.assertFalse(harness_download.availability('shannon')['available'])
            record.write_text(json.dumps({**spec,'tool':{'sha256':'b'*64,'bytes':3}}))
            self.assertFalse(harness_download.availability('shannon')['available'])
            (root/('b'*64+'.tar.gz')).write_bytes(b'123')
            self.assertTrue(harness_download.availability('shannon')['available'])
            (root/('b'*64+'.tar.gz')).write_bytes(b'12')
            self.assertFalse(harness_download.availability('shannon')['available'])

if __name__=='__main__':unittest.main()
