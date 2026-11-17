import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('console_server', Path(__file__).resolve().parents[1] / 'server.py')
server = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = server
spec.loader.exec_module(server)


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        server.ACTIVE = None
        server.JOBS.clear()
        server.DEMO_DONE.clear()

    def test_demo_can_run_without_project_or_key(self):
        with patch.dict('os.environ', {}, clear=True):
            state = server.snapshot('demo')
        self.assertFalse(state['api_ready'])
        self.assertEqual(state['assets']['docker']['assessment']['status'], 'exposure_conditions_present')
        self.assertFalse(state['assets']['docker']['stale'])

    def test_demo_never_launches_subprocess_or_api_and_requires_approval(self):
        job = {'mode': 'demo', 'action': 'execute', 'asset': 'docker', 'status': 'running', 'id': 'test'}
        server.JOBS['test'] = job
        with patch.object(server.subprocess, 'Popen', side_effect=AssertionError('No subprocess in demo')), patch.object(server.urllib.request, 'urlopen', side_effect=AssertionError('No network in demo')), patch.object(server.time, 'sleep'):
            thread = threading.Thread(target=server.demo_worker, args=(job,))
            thread.start()
            for _ in range(1000):
                if job.get('status') == 'waiting_approval':
                    break
                threading.Event().wait(.001)
            self.assertEqual(job['status'], 'waiting_approval')
            self.assertNotIn('docker', server.DEMO_DONE)
            with self.assertRaises(ValueError):
                server.approve({'id': 'test', 'approval_token': job['approval_token'], 'phrase': 'wrong'})
            server.approve({'id': 'test', 'approval_token': job['approval_token'], 'phrase': 'APROBAR'})
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertIn('docker', server.DEMO_DONE)

    def test_live_changed_evidence_blocks_approval(self):
        process = Mock()
        job = {'id': 'live', 'mode': 'live', 'asset': 'docker', 'status': 'waiting_approval', 'phrase': 'APROBAR', 'approval_token': 'token', '_digest': 'old', '_process': process}
        server.JOBS['live'] = job
        with patch.object(server, 'validate_and_digest', return_value='changed'):
            with self.assertRaisesRegex(ValueError, 'Cambió'):
                server.approve({'id': 'live', 'approval_token': 'token', 'phrase': 'APROBAR'})
        process.stdin.write.assert_not_called()

    def test_live_stale_evidence_blocks_approval(self):
        process = Mock()
        server.JOBS['live'] = {'id': 'live', 'mode': 'live', 'asset': 'kernel', 'status': 'waiting_approval', 'phrase': 'APROBAR REINICIO', 'approval_token': 'token', '_digest': 'old', '_process': process}
        with patch.object(server, 'validate_and_digest', side_effect=ValueError('Evidencia antigua')):
            with self.assertRaisesRegex(ValueError, 'antigua'):
                server.approve({'id': 'live', 'approval_token': 'token', 'phrase': 'APROBAR REINICIO'})
        process.stdin.write.assert_not_called()

    def test_live_approval_is_one_use(self):
        process = Mock()
        process.poll.return_value = None
        server.JOBS['live'] = {'id': 'live', 'mode': 'live', 'asset': 'docker', 'status': 'waiting_approval', 'phrase': 'APROBAR', 'approval_token': 'token', '_digest': 'same', '_process': process}
        data = {'id': 'live', 'approval_token': 'token', 'phrase': 'APROBAR'}
        with patch.object(server, 'validate_and_digest', return_value='same'):
            server.approve(data)
            with self.assertRaises(ValueError):
                server.approve(data)
        process.stdin.write.assert_called_once_with(b'APROBAR\n')

    def test_cancel_never_sends_approval(self):
        process = Mock()
        process.poll.return_value = None
        server.JOBS['live'] = {'id': 'live', 'mode': 'live', 'asset': 'docker', 'status': 'waiting_approval', 'phrase': 'APROBAR', 'approval_token': 'token', '_process': process}
        server.approve({'id': 'live', 'approval_token': 'token'}, cancel=True)
        process.stdin.write.assert_called_once_with(b'\n')

    def test_arbitrary_actions_and_assets_are_rejected(self):
        for data in ({'action': 'shell', 'asset': 'docker', 'mode': 'live'}, {'action': 'execute', 'asset': '../../etc/passwd', 'mode': 'live'}, {'action': 'execute', 'asset': 'kernel', 'mode': 'other'}):
            with self.assertRaises(ValueError):
                server.start_job(data)

    def test_busy_blocks_second_job(self):
        server.ACTIVE = 'running'
        with self.assertRaisesRegex(ValueError, 'curso'):
            server.start_job({'action': 'execute', 'asset': 'docker', 'mode': 'demo'})

    def test_http_origin_and_token_are_required(self):
        handler = object.__new__(server.Handler)
        handler.server = Mock(server_port=8765)
        handler.send = Mock()
        for headers in (
            {'Host': '127.0.0.1:8765', 'Origin': 'https://evil.example', 'X-Secops-Token': server.TOKEN},
            {'Host': 'evil.example:8765', 'Origin': 'http://127.0.0.1:8765', 'X-Secops-Token': server.TOKEN},
            {'Host': '127.0.0.1:8765', 'Origin': 'http://127.0.0.1:8765'},
        ):
            handler.headers = headers
            handler.do_POST()
            self.assertEqual(handler.send.call_args.args[0], 403)

    def test_noncurrent_plan_is_not_displayed_as_current(self):
        with patch.object(server, 'read_json', side_effect=lambda path, default=None: {'asset_id': 'ssh-vulnerable', 'collected_at': '2026-11-07T00:00:00+00:00'} if path.name.endswith('inventory.json') else {'inventory_collected_at': 'different'}):
            state = server.snapshot('live')
        self.assertEqual(state['assets']['docker']['plan'], {})
        self.assertTrue(state['assets']['docker']['stale'])

    def test_existing_cli_prompt_is_bridged_only_after_approval(self):
        # A real local child process, but no SSH, API or laboratory scripts.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.venv/bin').mkdir(parents=True)
            os.symlink(sys.executable, root / '.venv/bin/python3')
            (root / 'coordinator.py').write_text(
                'print("Propuesta compatible con la política.", flush=True)\n'
                'answer = input("Escribe APROBAR para continuar: ")\n'
                'print("received=" + answer, flush=True)\n'
                'raise SystemExit(0 if answer == "APROBAR" else 1)\n'
            )
            job = {'id': 'bridge', 'mode': 'live', 'action': 'execute', 'asset': 'docker', 'status': 'running', 'log': ''}
            server.JOBS['bridge'] = job
            with patch.object(server, 'BASE', root), patch.object(server, 'validate_and_digest', return_value='same'), patch.object(server, 'snapshot', return_value={'assets': {'docker': {'assessment': {'status': 'password_authentication_mitigated'}}}}):
                thread = threading.Thread(target=server.worker, args=(job,))
                thread.start()
                for _ in range(2000):
                    if job['status'] in ('waiting_approval', 'failed'):
                        break
                    threading.Event().wait(.002)
                self.assertEqual(job['status'], 'waiting_approval', job)
                self.assertNotIn('received=', job['log'])
                server.approve({'id': 'bridge', 'approval_token': job['approval_token'], 'phrase': 'APROBAR'})
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(job['status'], 'completed', job)
                self.assertIn('received=APROBAR', job['log'])
                self.assertNotIn('_process', server.public_job(job))

    def test_chat_separates_evaluator_flag_from_completed_execution(self):
        state = {'inventory': {'container': {'image_id': 'image-1'}},
                 'assessment': {'action_executed': False, 'status': 'password_authentication_mitigated'}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / 'reports/execution-20261107T191753Z'
            folder.mkdir(parents=True)
            (folder / 'execution.json').write_text(json.dumps({
                'plan': {'proposal': {'asset_id': 'ssh-vulnerable', 'recommended_runbook': 'disable-ssh-password-authentication'}},
                'before': {'container': {'image_id': 'image-1'}},
                'status': 'completed', 'approved': True,
                'after_assessment': {'status': 'password_authentication_mitigated'},
                'stdout': 'sensitive raw logs must not be forwarded',
            }))
            unrelated = root / 'reports/kernel-execution-20261107T192201Z'
            unrelated.mkdir()
            (unrelated / 'execution.json').write_text(json.dumps({
                'plan': {'proposal': {'asset_id': 'secops-kernel-lab'}}, 'status': 'completed'
            }))
            with patch.object(server, 'BASE', root):
                context = server.chat_context('docker', '¿Se ejecutó?', state, 'runbook')
        self.assertNotIn('action_executed', context['state']['assessment'])
        self.assertFalse(context['evaluator_semantics']['collector_performed_remediation'])
        records = context['execution_history']['records']
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['status'], 'completed')
        self.assertTrue(records[0]['same_image_id_as_current_inventory'])
        self.assertNotIn('sensitive raw logs', json.dumps(context))
        self.assertIn('action_executed', state['assessment'])  # no mutation of source evidence

    def test_missing_audit_is_unknown_not_never_executed(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(server, 'BASE', Path(directory)):
            context = server.chat_context('docker', '¿Se ejecutó?', {'inventory': {}, 'assessment': {}}, 'runbook')
        self.assertEqual(context['execution_history']['records'], [])
        self.assertIn('No records does not mean never executed', context['execution_history']['interpretation'])
        self.assertIn('not an empty password', context['case_context'])


if __name__ == '__main__':
    unittest.main()
