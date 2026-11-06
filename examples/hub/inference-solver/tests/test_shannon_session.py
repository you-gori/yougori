"""Shannon's interactive lifecycle and quiet worker output, without a scan."""
import argparse
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'site/harnesses'))
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


if __name__=='__main__': unittest.main()
