#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo 'Build the native model runtime on macOS.' >&2; exit 1; }
revision=e117148a41d8e9bedb72e4c6c3f003ab0fe7f857 # llama.cpp b11425
root="$PWD/build/macos-model"
source="$root/source"
output="$root/runtime"
mkdir -p "$root" "$output"
if [[ ! -d "$source/.git" ]]; then git init "$source"; fi
git -C "$source" fetch --depth=1 https://github.com/ggml-org/llama.cpp.git "$revision"
git -C "$source" checkout --detach FETCH_HEAD
[[ "$(git -C "$source" rev-parse HEAD)" == "$revision" ]]
metal=OFF
[[ "$(uname -m)" != arm64 ]] || metal=ON
cmake -S "$source" -B "$root/build" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 -DBUILD_SHARED_LIBS=OFF \
  -DGGML_METAL="$metal" -DGGML_METAL_EMBED_LIBRARY=ON -DGGML_ACCELERATE=ON \
  -DGGML_NATIVE=OFF -DGGML_OPENMP=OFF -DLLAMA_OPENSSL=OFF -DLLAMA_SUBPROCESS=OFF \
  -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF -DLLAMA_BUILD_APP=OFF \
  -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_SERVER=ON
cmake --build "$root/build" --config Release --target llama-server --parallel 3
cp "$root/build/bin/llama-server" "$output/llama-server"
clang -std=c11 -D_DARWIN_C_SOURCE -Wall -Wextra -Werror -O2 -mmacosx-version-min=14.0 \
  runtime/macos/supervise.c -o "$output/yougori-supervise"
cp "$source/LICENSE" "$output/LICENSE.llama.cpp"
printf '%s\n' "$revision" > "$output/REVISION"
identity=${YOUGORI_MAC_SIGNING_IDENTITY:--}
options=(--force --options runtime --sign "$identity")
[[ "$identity" == - ]] || options+=(--timestamp)
for binary in llama-server yougori-supervise; do
  codesign "${options[@]}" "$output/$binary"
  codesign --verify --strict "$output/$binary"
done
(cd "$output"; shasum -a 256 llama-server yougori-supervise LICENSE.llama.cpp REVISION > SHA256SUMS)
git -C "$source" archive --format=tar "$revision" > "$root/llama.cpp-b11425-source.tar"
echo "Native model runtime: $output"
