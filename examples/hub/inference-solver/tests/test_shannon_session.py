"""Shannon's interactive lifecycle and quiet worker output, without a scan, and the bash timeout of
its pinned worker as the installer builds it."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HARNESSES = Path(__file__).resolve().parents[1]/'site/harnesses'
sys.path.insert(0,str(HARNESSES))
import install_shannon
import shannon_cli


class Session(unittest.TestCase):
    def args(self):
        return argparse.Namespace(model='local/model',target=None,validate_model=False,
                                  config=None,context_budget=32768,verbose=False)

    def test_stays_open_between_two_explicit_checks_and_does_not_scan(self):
        with patch('builtins.input',side_effect=['help','check','check','exit']), \
             patch.object(shannon_cli,'run_once',return_value=0) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(shannon_cli.session(self.args()),0)
        self.assertEqual(run.call_count,2)
        self.assertTrue(all(c.args[0].validate_model and c.args[0].target is None for c in run.call_args_list))

    def test_empty_workspace_and_external_target_do_not_start_scan(self):
        for env,command in [({'SOLVER_EMPTY_WORKSPACE':'1'},'scan http://localhost:8081'),
                            ({},'scan https://example.com')]:
            with self.subTest(command=command),patch.dict(os.environ,env,clear=True), \
                 patch('builtins.input',side_effect=[command,'exit']),patch.object(shannon_cli,'run_once') as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(shannon_cli.session(self.args()),0)
                run.assert_not_called()

    def test_selected_workspace_scan_requires_explicit_command(self):
        with patch.dict(os.environ,{},clear=True),patch('builtins.input',side_effect=['scan http://localhost:8081','exit']), \
             patch.object(shannon_cli,'run_once',return_value=0) as run,contextlib.redirect_stdout(io.StringIO()):
            shannon_cli.session(self.args())
        self.assertEqual(run.call_count,1)
        self.assertFalse(run.call_args.args[0].validate_model)
        self.assertEqual(run.call_args.args[0].target,'http://localhost:8081')

    def test_eof_closes_instead_of_looping(self):
        with patch('builtins.input',side_effect=EOFError),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(shannon_cli.session(self.args()),0)

    def test_one_shot_without_a_task_never_starts_worker(self):
        with patch.object(shannon_cli,'worker') as run,self.assertRaisesRegex(ValueError,'target is required'):
            shannon_cli.run_once(self.args())
        run.assert_not_called()

    @unittest.skipUnless(os.name=='posix','The worker wrapper runs only inside Linux VMs')
    def test_worker_saves_internal_logs_and_preserves_success_and_error_codes(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for code in (0,3):
                log=root/'worker.log';output=io.StringIO()
                program="print('1970-01-01 [INFO] internal taskToken: TEST');print('Model validated.' if not "+str(code)+" else 'Scan failed.');raise SystemExit("+str(code)+")"
                with contextlib.redirect_stdout(output):
                    self.assertEqual(shannon_cli.worker([sys.executable,'-c',program],dict(os.environ),root,log),code)
                self.assertIn('internal taskToken',log.read_text())
                self.assertNotIn('taskToken',output.getvalue())
                self.assertIn('Model validated.' if not code else 'exit 3',output.getvalue())


# Shannon's bash-timeout extension at the pinned commit (packages.json, shannon), byte for byte:
# apps/worker/src/ai/extensions/bash-timeout/index.ts.
PINNED_COMMIT = 'b9744f6cecc5429333873b86a6762f1d70c54fc2'
PINNED_BASH_TIMEOUT = """/**
 * pi extension: enforce a bounded timeout on every `bash` tool call.
 *
 * pi's built-in bash tool accepts an optional `timeout` (in seconds) but applies
 * NO default and NO upper bound \u2014 an unbounded command (e.g. a `playwright-cli`
 * browser action that never returns) hangs the agent indefinitely. This extension
 * registers a `tool_call` pre-execution handler that blocks any `bash` invocation
 * that omits `timeout` or sets it above the maximum, returning a message that tells
 * the model how to re-run the command correctly.
 */

import type { ExtensionAPI, ToolCallEvent, ToolCallEventResult } from '@earendil-works/pi-coding-agent';
import { isToolCallEventType } from '@earendil-works/pi-coding-agent';

/** Recommended timeout (seconds) suggested to the model when it omits one. */
const DEFAULT_TIMEOUT_SECONDS = 120;

/** Hard upper bound (seconds) a single bash command may run. */
const MAX_TIMEOUT_SECONDS = 600;

function evaluateBashTimeout(timeout: number | undefined): ToolCallEventResult | undefined {
  const hasValidTimeout = typeof timeout === 'number' && Number.isFinite(timeout) && timeout > 0;
  if (!hasValidTimeout) {
    return {
      block: true,
      reason: `A timeout in seconds is required for the bash tool. The bash tool was not executed. Use the default of ${DEFAULT_TIMEOUT_SECONDS} seconds, or up to a maximum of ${MAX_TIMEOUT_SECONDS} seconds.`,
    };
  }

  if (timeout > MAX_TIMEOUT_SECONDS) {
    return {
      block: true,
      reason: `bash 'timeout' ${timeout}s exceeds max ${MAX_TIMEOUT_SECONDS}s. Default ${DEFAULT_TIMEOUT_SECONDS}s, max ${MAX_TIMEOUT_SECONDS}s.`,
    };
  }

  return undefined;
}

export default function bashTimeoutExtension(pi: ExtensionAPI): void {
  pi.on('tool_call', (event: ToolCallEvent): ToolCallEventResult | undefined => {
    if (!isToolCallEventType('bash', event)) {
      return undefined;
    }
    return evaluateBashTimeout(event.input.timeout);
  });
}
"""
# Its handler once patched: a bash call without a timeout gets the default, then the same check.
PATCHED_HANDLER = """  pi.on('tool_call', (event: ToolCallEvent): ToolCallEventResult | undefined => {
    if (!isToolCallEventType('bash', event)) {
      return undefined;
    }
    if (event.input.timeout == null) event.input.timeout = DEFAULT_TIMEOUT_SECONDS;
    return evaluateBashTimeout(event.input.timeout);
  });
}
"""


class BashTimeout(unittest.TestCase):
    """Round 2 with Gemma: Shannon refused all 31 bash calls of a pre-recon attempt (ls -F, each in
    0-1 ms) because they gave no timeout, so nothing reached the practice app. The installer gives
    such a call Shannon's own default instead."""

    def source(self,text):
        """A source tree holding `text` as the bash-timeout extension; its path."""
        root=Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree,root,ignore_errors=True)
        path=root/install_shannon.BASH_TIMEOUT
        path.parent.mkdir(parents=True)
        path.write_bytes(text.encode('utf-8'))
        return root,path

    def test_the_patch_is_for_the_pinned_shannon(self):
        self.assertEqual(json.loads((HARNESSES/'packages.json').read_text(encoding='utf-8'))['shannon']['commit'],PINNED_COMMIT,
                         'A new Shannon pin: read its bash-timeout extension again, then update this copy and its hash.')
        self.assertEqual(hashlib.sha256(PINNED_BASH_TIMEOUT.encode('utf-8')).hexdigest(),install_shannon.BASH_TIMEOUT_SHA256)

    def test_a_bash_call_without_a_timeout_runs_with_shannons_default(self):
        root,path=self.source(PINNED_BASH_TIMEOUT)
        install_shannon.default_bash_timeout(root)
        patched=path.read_bytes().decode('utf-8')
        self.assertTrue(patched.endswith(PATCHED_HANDLER),patched)
        # Only that line is new; the default is within Shannon's limit, above which it still refuses.
        self.assertEqual(patched.replace(install_shannon.BASH_TIMEOUT_DEFAULT,'',1),PINNED_BASH_TIMEOUT)
        for kept in ('const DEFAULT_TIMEOUT_SECONDS = 120;','const MAX_TIMEOUT_SECONDS = 600;','if (timeout > MAX_TIMEOUT_SECONDS) {'):
            self.assertIn(kept,patched)

    def test_an_extension_that_is_not_the_pinned_one_stops_the_build_as_it_is(self):
        changed=PINNED_BASH_TIMEOUT.replace('const DEFAULT_TIMEOUT_SECONDS = 120;','const DEFAULT_TIMEOUT_SECONDS = 900;')
        moved=PINNED_BASH_TIMEOUT.replace('    return evaluateBashTimeout(event.input.timeout);\n',
                                          '    const verdict = evaluateBashTimeout(event.input.timeout);\n    return verdict;\n')
        twice=PINNED_BASH_TIMEOUT.replace(install_shannon.BASH_TIMEOUT_CHECK,install_shannon.BASH_TIMEOUT_DEFAULT+install_shannon.BASH_TIMEOUT_CHECK)
        for name,text in (('another default',changed),('another handler',moved),('patched already',twice)):
            with self.subTest(name):
                root,path=self.source(text)
                with self.assertRaisesRegex(ValueError,'Pinned Shannon source changed'):
                    install_shannon.default_bash_timeout(root)
                self.assertEqual(path.read_bytes(),text.encode('utf-8'))

    def test_the_build_patches_it_before_compiling_the_worker(self):
        root,path=self.source(PINNED_BASH_TIMEOUT)
        (root/'apps/worker/src/paths.ts').write_text("export const MODELS_CONFIG_PATH = '/app/models.json';\n",encoding='utf-8')
        (root/'apps/worker/src/ai/models.ts').write_text('allowModelNetwork: true,\n',encoding='utf-8')
        seen=[]

        class Compiling(Exception):
            pass

        def run(argv,**options):
            seen.append(path.read_bytes().decode('utf-8'))
            raise Compiling
        with patch.object(install_shannon.subprocess,'run',side_effect=run),self.assertRaises(Compiling):
            install_shannon.build(root,{})
        self.assertEqual(len(seen),1)
        self.assertTrue(seen[0].endswith(PATCHED_HANDLER))


if __name__=='__main__': unittest.main()
