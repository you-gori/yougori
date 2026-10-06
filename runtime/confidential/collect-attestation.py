#!/usr/bin/env python3
"""Bounded descriptor-to-vendor adapter; requires a pinned collector inside a CVM.

This wrapper is not a verifier and does not claim that hardware is confidential.
It never sees prompts, replies, private age keys or private signing keys.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

FIELDS = {'version', 'nodeId', 'model', 'revision', 'nonce', 'recipient', 'signingKey', 'issuedAt', 'expiresAt'}


def command(manifest, descriptor):
    if set(manifest) != {'binary', 'binarySha256', 'config', 'policyIds'}:
        raise ValueError('Invalid collector manifest')
    binary, config = Path(manifest['binary']), Path(manifest['config'])
    if not binary.is_absolute() or not config.is_absolute():
        raise ValueError('Collector paths must be absolute')
    if not re.fullmatch(r'[a-f0-9]{64}', manifest['binarySha256']):
        raise ValueError('Collector must be pinned by SHA256')
    digest = hashlib.sha256()
    with binary.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    if digest.hexdigest() != manifest['binarySha256']:
        raise ValueError('Collector binary did not match its image manifest')
    if os.name == 'posix' and config.stat().st_mode & 0o077:
        raise ValueError('Vendor credential configuration must be private')
    policies = manifest['policyIds']
    if not isinstance(policies, list) or not policies or not all(isinstance(p, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', p) for p in policies):
        raise ValueError('A composite appraisal policy is required')
    if not isinstance(descriptor, dict) or set(descriptor) != FIELDS or descriptor['version'] != 1:
        raise ValueError('Invalid runtime descriptor')
    for field in ('nonce', 'signingKey'):
        if not isinstance(descriptor[field], str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', descriptor[field]):
            raise ValueError('Invalid runtime public binding')
    encoded = base64.b64encode(json.dumps(descriptor, separators=(',', ':')).encode()).decode('ascii')
    return [str(binary), 'token', '--config', str(config), '--user-data', encoded,
            '--tdx', '--nvgpu', '--policy-ids', ','.join(policies), '--policy-must-match',
            '--token-signing-alg', 'PS384']


def bounded_token(process):
    deadline = time.monotonic() + 25
    chunks, size = [], 0
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError('Vendor collector deadline exceeded')
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > 262144:
                raise ValueError('Vendor token exceeds its limit')
            chunks.append(chunk)
    if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
        raise ValueError('Vendor attestation failed')
    return b''.join(chunks)


def main():
    try:
        if sys.platform != 'linux':
            raise ValueError('The hardware collector requires the approved Linux CVM')
        manifest_path = Path(os.environ['YOUGORI_ATTESTATION_MANIFEST'])
        if manifest_path.stat().st_size > 65536:
            raise ValueError('Collector manifest exceeds its limit')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        wire = sys.stdin.buffer.read(65537)
        if len(wire) > 65536:
            raise ValueError('Descriptor exceeds its limit')
        descriptor = json.loads(wire)
        # Command arguments contain only public evidence binding. Vendor API
        # credentials stay in the protected configuration file, never argv.
        process = subprocess.Popen(command(manifest, descriptor), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            # The native runner also enforces a 30s collector deadline and output
            # cap. This child is part of the pinned, measured image.
            output = bounded_token(process)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        token = output.decode('ascii').strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token):
            raise ValueError('Vendor did not return a compact attestation JWT')
        sys.stdout.write(token)
    except Exception:
        # Raw vendor errors can include API keys or configuration. Suppress them.
        print('Confidential attestation collection failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
