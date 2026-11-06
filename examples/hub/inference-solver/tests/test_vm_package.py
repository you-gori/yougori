"""Integrity and extraction boundaries for the VM's private package transfer."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'site/harnesses'))
from vm_package import Package


class Packages(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def archive(self,name='tool/bin/app',link=None):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as stream:
            info=tarfile.TarInfo(name)
            if link:info.type=tarfile.SYMTYPE;info.linkname=link
            else:info.size=2;info.mode=0o755
            stream.addfile(info,None if link else io.BytesIO(b'OK'))
        return output.getvalue()

    def package(self,raw):
        (self.root/'tool-package.json').write_text(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
        return Package(self.root)

    def finish(self,package,raw):
        package.chunk({'offset':0,'data':base64.b64encode(raw).decode()});package.finish()
        deadline=time.monotonic()+5
        while package.status()['phase']=='checking' and time.monotonic()<deadline:time.sleep(.01)
        return package.status()

    def test_verified_package_installs_executable_and_removes_download(self):
        raw=self.archive();p=self.package(raw)
        self.assertEqual(self.finish(p,raw)['phase'],'ready')
        self.assertEqual((self.root/'tool/bin/app').read_bytes(),b'OK')
        self.assertFalse(p.path.exists())
        p.finish() # Lost finish acknowledgement can be retried safely.

    def test_wrong_offset_incomplete_and_oversized_chunk_are_refused(self):
        raw=self.archive();p=self.package(raw)
        with self.assertRaises(ValueError):p.finish()
        with self.assertRaises(ValueError):p.chunk({'offset':1,'data':'T0s='})
        with self.assertRaises(ValueError):p.chunk({'offset':0,'data':base64.b64encode(raw+b'extra').decode()})
        self.assertEqual(p.status()['offset'],0)

    def test_checksum_mismatch_never_extracts(self):
        raw=self.archive();p=self.package(raw)
        self.assertEqual(self.finish(p,raw[:-1]+bytes([raw[-1]^1]))['phase'],'failed')
        self.assertFalse((self.root/'tool').exists())

    def test_path_and_symlink_escape_never_installs(self):
        for name,link in [('../escape',None),('/absolute',None),('tool/link','/etc/passwd'),('tool/../outside',None)]:
            with self.subTest(name=name,link=link):
                raw=self.archive(name,link);p=self.package(raw)
                self.assertEqual(self.finish(p,raw)['phase'],'failed')
                self.assertFalse((self.root/'tool/link').exists())


if __name__=='__main__':unittest.main()
