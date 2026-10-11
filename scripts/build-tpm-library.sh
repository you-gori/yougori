#!/usr/bin/env bash
set -euo pipefail
# Run inside MSYS2 UCRT64. Outputs are build artifacts, not source edits.
repo=$(cd "$(dirname "$0")/.." && pwd)
source_dir="$repo/build/runtime-cache/ms-tpm-20-ref/TPMCmd"
output="$repo/build/secure-runtime/tpm"
mkdir -p "$output/objects"
includes=(Platform/include Platform/include/prototypes tpm/include
  tpm/include/platform_interface tpm/include/platform_interface/prototypes
  tpm/include/private tpm/include/private/prototypes tpm/include/public
  tpm/cryptolibs tpm/cryptolibs/common/include tpm/cryptolibs/Ossl/include
  tpm/cryptolibs/TpmBigNum/include TpmConfiguration)
flags=(-O2 -ffunction-sections -fdata-sections -DNDEBUG -DHASH_LIB=Ossl -DSYM_LIB=Ossl -DMATH_LIB=TpmBigNum
  "-ffile-prefix-map=$repo=/yougori" "-ffile-prefix-map=$(cygpath -m "$repo")=/yougori"
  -DBN_MATH_LIB=Ossl -Wno-deprecated-declarations -I"$(cygpath -m "$repo/runtime/security")")
for include in "${includes[@]}"; do flags+=(-I"$(cygpath -m "$source_dir/$include")"); done
export repo source_dir output
printf '"%s"\n' "${flags[@]}" > "$output/compiler.rsp"
cd "$source_dir"
compile() {
  local source="$1" name="${1//\//_}"
  gcc @"$output/compiler.rsp" -c "$source" -o "$output/objects/${name%.c}.o"
}
export -f compile
find tpm/src tpm/cryptolibs/Ossl tpm/cryptolibs/TpmBigNum Platform/src -name '*.c' \
  ! -name Entropy.c ! -name NVMem.c -print0 | xargs -0 -P 8 -I '{}' bash -c 'compile "$1"' _ '{}'
for name in tpm-platform tpm-library; do
  gcc @"$output/compiler.rsp" -c "$repo/runtime/security/$name.c" -o "$output/objects/$name.o"
done
for object in "$output/objects/"*.o; do
  # Upstream disables the unfinished CertifyX509 command. These two optional
  # translation units otherwise reference its deliberately absent helpers.
  case "$object" in *_X509_X509_ECC.o|*_X509_X509_RSA.o) continue ;; esac
  printf '"%s"\n' "$(cygpath -m "$object")"
done > "$output/link.rsp"
gcc -shared -s -Wl,--gc-sections -o "$output/yougori-tpm.dll" @"$output/link.rsp" -lcrypto -lbcrypt -lwinpthread
gcc -O2 -s "-ffile-prefix-map=$repo=/yougori" "-ffile-prefix-map=$(cygpath -m "$repo")=/yougori" -I"$repo/runtime/security" "$repo/runtime/security/tpm-init.c" -o "$output/yougori-tpm-init.exe"
gcc -O2 -s -Wall -Wextra -Werror "-ffile-prefix-map=$repo=/yougori" "-ffile-prefix-map=$(cygpath -m "$repo")=/yougori" -I"$repo/runtime/security" "$repo/runtime/security/tpm-worker.c" -o "$output/yougori-tpm-worker.exe"
echo "Built private TPM library: $output/yougori-tpm.dll"
