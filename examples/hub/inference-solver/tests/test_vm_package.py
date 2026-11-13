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


class Fixture:
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


class Packages(Fixture,unittest.TestCase):
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


class Declared(Fixture,unittest.TestCase):
    """The Yougori harness's base image pins no package: the launcher declares the pack first."""

    def declared(self,raw,harness='opencode'):
        return {'harness':harness,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}

    def test_the_base_waits_for_the_declaration_before_any_chunk(self):
        raw=self.archive();p=Package(self.root,shared=True)
        self.assertEqual(p.status(),{'phase':'expecting','offset':0,'error':''})
        with self.assertRaises(ValueError):p.chunk({'offset':0,'data':base64.b64encode(raw).decode()})
        with self.assertRaises(ValueError):p.finish()
        self.assertFalse(p.path.exists())
        self.assertEqual(p.expect(self.declared(raw)),{'phase':'waiting','offset':0,'error':'','harness':'opencode'})
        self.assertEqual(self.finish(p,raw),{'phase':'ready','offset':len(raw),'error':'','harness':'opencode'})
        self.assertEqual((self.root/'tool/bin/app').read_bytes(),b'OK')
        self.assertEqual(p.harness,'opencode')

    def test_the_declaration_is_taken_once(self):
        raw=self.archive();p=Package(self.root,shared=True);declared=self.declared(raw)
        p.expect(declared)
        # A lost reply: the same declaration again changes nothing, before or after chunks.
        self.assertEqual(p.expect(dict(declared))['phase'],'waiting')
        p.chunk({'offset':0,'data':base64.b64encode(raw[:5]).decode()})
        self.assertEqual(p.expect(dict(declared)),{'phase':'waiting','offset':5,'error':'','harness':'opencode'})
        for other in ({**declared,'harness':'kilo'},{**declared,'sha256':'0'*64},{**declared,'bytes':len(raw)+1},{'harness':'opencode'}):
            with self.subTest(other=other),self.assertRaises(ValueError):p.expect(other)
        self.assertEqual((p.harness,p.spec,p.offset),('opencode',{'sha256':declared['sha256'],'bytes':len(raw)},5))

    def test_a_harness_without_a_pack_is_ready_at_once(self):
        p=Package(self.root,shared=True)
        self.assertEqual(p.expect({'harness':'yougori'}),{'phase':'ready','offset':0,'error':'','harness':'yougori'})
        self.assertEqual(p.expect({'harness':'yougori'})['phase'],'ready')
        with self.assertRaises(ValueError):p.chunk({'offset':0,'data':'T0s='})
        with self.assertRaises(ValueError):p.expect({'harness':'yougori','sha256':'a'*64,'bytes':3})
        p.finish()  # Nothing to finish: ready stays ready.
        self.assertFalse((self.root/'tool').exists())

    def test_a_declared_pack_is_verified_like_a_pinned_one(self):
        raw=self.archive();p=Package(self.root,shared=True)
        p.expect(self.declared(raw))
        self.assertEqual(self.finish(p,raw[:-1]+bytes([raw[-1]^1]))['phase'],'failed')
        self.assertFalse((self.root/'tool').exists())
        self.assertFalse(p.path.exists())
        with self.assertRaises(ValueError):p.expect(self.declared(raw,'kilo'))
        for name,link in [('../escape',None),('/absolute',None),('tool/link','/etc/passwd'),('other/app',None)]:
            with self.subTest(name=name,link=link):
                raw=self.archive(name,link);p=Package(self.root,shared=True)
                p.expect(self.declared(raw))
                self.assertEqual(self.finish(p,raw)['phase'],'failed')
                self.assertFalse((self.root/'tool/link').exists() or (self.root/'other').exists())

    def test_a_switch_puts_the_next_pack_in_the_place_of_the_one_before(self):
        """The screen's /harness: with `replace`, another declaration once the pack before is whole."""
        first=self.archive();p=Package(self.root,shared=True)
        p.expect(self.declared(first));self.finish(p,first)
        (self.root/'source').mkdir();(self.root/'source/LICENSE').write_text('MIT')
        second=self.archive('tool/bin/next')
        # Not while the pack before is still arriving, nor without a switch.
        with self.assertRaises(ValueError):p.expect(self.declared(second,'kilo'))
        self.assertEqual(p.expect(self.declared(second,'kilo'),replace=True),{'phase':'waiting','offset':0,'error':'','harness':'kilo'})
        self.assertFalse((self.root/'tool').exists() or (self.root/'source').exists())
        with self.assertRaisesRegex(ValueError,'still arriving'):p.expect(self.declared(first),replace=True)
        self.assertEqual(self.finish(p,second)['phase'],'ready')
        self.assertTrue((self.root/'tool/bin/next').is_file())
        # Yougori's own agent needs no pack: the one before stays, unused, until another replaces it.
        self.assertEqual(p.expect({'harness':'yougori'},replace=True)['phase'],'ready')
        self.assertTrue((self.root/'tool/bin/next').is_file())
        self.assertEqual(p.expect(self.declared(first),replace=True)['phase'],'waiting')
        self.assertFalse((self.root/'tool').exists())

    def test_invalid_declarations_and_images_that_take_none_are_refused(self):
        p=Package(self.root,shared=True);digest='a'*64
        for bad in (None,[],{},{'harness':'Bad'},{'harness':'../x'},{'harness':'a'*33},{'harness':7},
                    {'harness':'opencode','sha256':'A'*64,'bytes':3},{'harness':'opencode','sha256':digest},
                    {'harness':'opencode','bytes':3},{'harness':'opencode','sha256':digest,'bytes':0},
                    {'harness':'opencode','sha256':digest,'bytes':True},{'harness':'opencode','sha256':digest,'bytes':(512<<20)+1},
                    {'harness':'opencode','sha256':digest,'bytes':'3'},{'harness':'opencode','extra':1}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):p.expect(bad)
        self.assertEqual((p.status()['phase'],p.harness),('expecting',None))
        # An image that pins its package takes no declaration, nor does one that needs no package.
        raw=self.archive();pinned=self.package(raw)
        shared_pinned=Package(self.root,shared=True)
        for package in (pinned,shared_pinned):
            with self.assertRaises(ValueError):package.expect(self.declared(raw))
            self.assertEqual(package.status()['phase'],'waiting')
        (self.root/'tool-package.json').unlink()
        plain=Package(self.root)
        with self.assertRaises(ValueError):plain.expect({'harness':'yougori'})
        self.assertEqual(plain.status(),{'phase':'ready','offset':0,'error':''})


if __name__=='__main__':unittest.main()
