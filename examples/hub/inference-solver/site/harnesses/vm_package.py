"""Bounded, hash-verified tool delivery inside an already isolated VM.

An image made for one harness pins its tool package (tool-package.json). The Yougori harness's
base image pins none: before any chunk, the launcher tells the VM which harness's pack to expect,
with its hash and size, or that the harness needs none (`expect`, taken once). The pack is then
received and checked exactly as a pinned one. When the person switches harness in the screen
(/harness), the launcher declares the next harness's pack (`expect` with `replace`): the pack
installed is removed first, then the next one arrives as the first did."""
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
import threading

HARNESS = re.compile(r"[a-z][a-z0-9-]{0,31}")
DIGEST = re.compile(r"[a-f0-9]{64}")
# The largest pack the launcher downloads (vm_host).
PACK_BYTES = 512 << 20


class Package:
    def __init__(self,root,shared=False):
        """`shared`: the image is the Yougori harness's base, which waits for the launcher's
        `expect` (unless the image pins a package itself); any other image without a pinned
        package has nothing to receive."""
        self.root=Path(root)
        spec=self.root/'tool-package.json'
        self.spec=json.loads(spec.read_text()) if spec.exists() else None
        # The harness whose pack the launcher declared (None until then, and for pinned images).
        self.harness=None
        self.phase='waiting' if self.spec else 'expecting' if shared else 'ready'
        self.offset=0
        self.error=''
        self.lock=threading.Lock()
        self.path=self.root/'tool-download.partial'

    def current(self):
        value={'phase':self.phase,'offset':self.offset,'error':self.error}
        if self.harness is not None: value['harness']=self.harness
        return value

    def status(self):
        with self.lock: return self.current()

    def expect(self,data,replace=False):
        """The launcher's word on what this VM runs: {"harness"} alone when that harness needs no
        pack, or with its pack's "sha256" and "bytes". Taken once, before any chunk; the same word
        again (a reply that was lost) changes nothing, and any other is refused. With `replace` (a
        switch the screen asked for, vm_guest), another word is taken once the installed pack is
        whole: that pack is removed first, so nothing of it is left to run."""
        if (not isinstance(data,dict) or set(data)-{'harness','sha256','bytes'} or not isinstance(data.get('harness'),str)
                or not HARNESS.fullmatch(data['harness'])):
            raise ValueError('Invalid pack declaration.')
        pack=None
        if 'sha256' in data or 'bytes' in data:
            if (not isinstance(data.get('sha256'),str) or not DIGEST.fullmatch(data['sha256'])
                    or type(data.get('bytes')) is not int or not 0<data['bytes']<=PACK_BYTES):
                raise ValueError('Invalid pack declaration.')
            pack={'sha256':data['sha256'],'bytes':data['bytes']}
        with self.lock:
            if self.harness is not None:
                if self.harness==data['harness'] and self.spec==pack:
                    return self.current()
                if not replace:
                    raise ValueError('This VM already expects another pack.')
                if self.phase not in ('ready','failed'):
                    raise ValueError('The pack before is still arriving.')
                if pack is not None:
                    # The next pack takes the place of the one before. A harness that needs no pack
                    # (Yougori's own agent) leaves it in place: nothing starts from it.
                    self.remove()
                self.offset=0;self.error=''
            elif self.phase!='expecting':
                raise ValueError('This VM does not take a pack declaration.')
            self.harness=data['harness']
            self.spec=pack
            self.phase='waiting' if pack else 'ready'
            return self.current()

    def remove(self):
        """Takes the installed pack out of the VM: its two roots, and a transfer left half-way."""
        for name in ('tool','source'):
            shutil.rmtree(self.root/name,ignore_errors=True)
            if (self.root/name).exists():
                raise ValueError('The pack before could not be removed. Restart this VM.')
        self.path.unlink(missing_ok=True)

    def chunk(self,data):
        with self.lock:
            if self.phase!='waiting' or type(data.get('offset')) is not int or data['offset']!=self.offset:
                raise ValueError('The tool package transfer is not at this offset.')
            raw=base64.b64decode(data.get('data',''),validate=True)
            if not 0<len(raw)<=2<<20 or self.offset+len(raw)>self.spec['bytes']:
                raise ValueError('Invalid tool package chunk.')
            with self.path.open('ab' if self.offset else 'wb') as stream: stream.write(raw)
            self.offset+=len(raw)
            return {'offset':self.offset}

    def finish(self):
        with self.lock:
            if self.phase in ('checking','ready'): return
            if self.phase!='waiting' or self.offset!=self.spec['bytes']: raise ValueError('The tool package is incomplete.')
            self.phase='checking'
            threading.Thread(target=self.extract,daemon=True).start()

    def extract(self):
        current='package verification'
        try:
            with self.path.open('rb') as stream:
                if hashlib.file_digest(stream,'sha256').hexdigest()!=self.spec['sha256']:
                    raise ValueError('Tool package checksum mismatch.')
            with tarfile.open(self.path) as archive:
                members=[];total=0
                for member in archive:
                    # Only the two package roots, with no devices/FIFOs or path
                    # escapes. Python's data filter also checks link targets.
                    parts=Path(member.name).parts
                    if not parts or parts[0] not in ('tool','source') or '..' in parts or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                        raise ValueError('Invalid tool package entry.')
                    total+=member.size
                    if total>1400<<20 or len(members)>=100000: raise ValueError('Tool package exceeds the VM extraction budget.')
                    members.append(member)
                def checked(member,destination):
                    nonlocal current
                    current=member.name
                    return tarfile.data_filter(member,destination)
                archive.extractall(self.root,members=members,filter=checked)
            with self.lock:self.phase='ready'
        except (OSError,ValueError,tarfile.TarError) as error:
            detail=('OS error '+str(error.errno)) if isinstance(error,OSError) else type(error).__name__+': '+str(error)[:300]
            with self.lock:self.phase='failed';self.error='The tool package could not be installed ('+detail+' at '+current[:240]+'). Restart this VM.'
        finally:self.path.unlink(missing_ok=True)
