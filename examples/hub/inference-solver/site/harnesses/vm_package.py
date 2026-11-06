"""Bounded, hash-verified tool delivery inside an already isolated VM."""
import base64
import hashlib
import json
from pathlib import Path
import tarfile
import threading


class Package:
    def __init__(self,root):
        self.root=Path(root)
        spec=self.root/'tool-package.json'
        self.spec=json.loads(spec.read_text()) if spec.exists() else None
        self.phase='waiting' if self.spec else 'ready'
        self.offset=0
        self.error=''
        self.lock=threading.Lock()
        self.path=self.root/'tool-download.partial'

    def status(self):
        with self.lock: return {'phase':self.phase,'offset':self.offset,'error':self.error}

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
