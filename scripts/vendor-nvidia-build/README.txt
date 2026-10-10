The CUDA runtime consumes NVIDIA Container Toolkit1.20.0 CDI generation/listing
and nvidia-cdi-hook, not nvidia-container-runtime. Rebuild only those two tools
from the exact verified upstream commit, with Go1.27.2 and frozen x/mod0.40.0.
The product release/API stays1.20.0. Binary version records the upstream commit
plus a Yougori security build marker; complete module patches and inputs remain
available for source review and relinking.

Use Python3.12+ on Linux AMD64 with the exact inputs.json compiler/native package
versions. CGO remains enabled, dynamically linking libc.so.6 because NVML loads
the WSL NVIDIA driver library with dlopen. Never replace it with static musl or
ship a Linux display driver. The host NVIDIA driver and WSL kernel remain host
dependencies and require their own maintained security updates.
On WSL with NVIDIA installed, run this build as root in a private build distro.
Only unchanged unit fixtures run in a separate private mount namespace hiding
the real WSL driver library mounts; actual CDI compatibility checks run against
the real driver outside that namespace. No host mount or workload is changed.

Preparation (updates only this folder's frozen modules):
  python3 scripts/vendor-nvidia-build/build.py --go /path/to/go1.27.2/bin/go \
    --prepare --work /fresh/native/prepare
Review modules/go.mod, go.sum, modules.patch and lock.json before building.

Actual build, tests, source/binary vulnerability scans and two independent builds:
  python3 scripts/vendor-nvidia-build/build.py --go /path/to/go1.27.2/bin/go \
    --work /fresh/native/build --output /fresh/output

The compiler's original official go1.27.2.linux-amd64.tar.gz must remain alongside
its extracted go/ directory for checksum verification. Source archives, package
source versions, module graph, test logs, raw scans and native linkage records
are preserved in the work directory. Archive contains exactly bin/nvidia-ctk and
bin/nvidia-cdi-hook with mode0755; manifest schema1 requires kind=nvidia-cdi.
This payload is separate from the ten-file OCI runtime payload.
