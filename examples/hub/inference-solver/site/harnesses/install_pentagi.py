"""Build the pinned PentAGI server with an explicit in-VM process backend."""
import os
from pathlib import Path
import shutil
import subprocess


def build(source,spec):
    backend=source/'backend'
    client=backend/'pkg/docker/client.go'
    original='func NewDockerClient(ctx context.Context, db database.Querier, cfg *config.Config) (DockerClient, error) {'
    text=client.read_text()
    if text.count(original)!=1: raise ValueError('Pinned PentAGI runtime constructor changed.')
    client.write_text(text.replace(original,original+'\n\treturn newYougoriVMClient(db)\n}\n\nfunc unusedContainerConstructor(ctx context.Context, db database.Querier, cfg *config.Config) (DockerClient, error) {'))
    shutil.copy2('/opt/solver/pentagi_vm.go',backend/'pkg/docker/yougori_vm.go')
    shutil.copy2('/opt/solver/pentagi_vm_test.go',backend/'pkg/docker/yougori_vm_test.go')
    environment={**os.environ,'CGO_ENABLED':'0','GOCACHE':'/home/node/.cache/go'}
    subprocess.run(['go','test','./pkg/docker','-run','^TestYougoriVM','-count=1'],cwd=backend,env=environment,check=True)
    subprocess.run(['go','build','-trimpath','-ldflags','-s -w','-o','/opt/solver/tool/bin/pentagi','./cmd/pentagi'],cwd=backend,env=environment,check=True)
    shutil.copy2(source/'LICENSE','/opt/solver/tool/PENTAGI-LICENSE')
    # The download includes the source revision and adapter. Build caches and
    # unrelated frontend assets are not needed by the terminal runtime.
    shutil.rmtree(source)
