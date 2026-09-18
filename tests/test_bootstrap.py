import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    from scripts import publisher_bootstrap as b
except ImportError:
    import bootstrap as b


class PublisherBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.specs = self.root / '.private-workflow-steps'
        self.specs.mkdir()
        self.output = self.root / 'public-output'
        self.environment = self.root / 'public-environment'
        self.env = dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_OUTPUT=str(self.output),
                        GITHUB_ENV=str(self.environment), GITHUB_JOB='test', GITHUB_REF='refs/heads/main')
        for name in ('RUNNER_DEBUG', 'ACTIONS_STEP_DEBUG', 'ACTIONS_RUNNER_DEBUG'):
            self.env.pop(name, None)

    def spec(self, command):
        (self.specs / 'fixture.job.0.json').write_text(json.dumps({'run': command}))

    def test_seeded_stdout_stderr_workflow_commands_and_summary_stay_private(self):
        secret = 'PRIVATE_SENTINEL_9eae881cb'
        self.spec('echo "'+secret+'"; echo "::error::'+secret+'" >&2; echo "'+secret+'" >> "$GITHUB_STEP_SUMMARY"; exit 17')
        result = io.StringIO()
        with contextlib.redirect_stdout(result):
            code = b.execute(self.root, 'fixture.job.0', self.env)
        self.assertEqual(code, 17)
        self.assertNotIn(secret, result.getvalue())
        self.assertIn(secret, (self.root / 'private-step-logs/test/fixture.job.0.log').read_text())
        self.assertFalse(self.output.exists())

    def test_metadata_requires_explicit_field_and_type(self):
        for text in ('unexpected=PRIVATE_SENTINEL', 'dataset_id=PRIVATE_SENTINEL',
                     'PATH=/tmp/evil', 'deploy_needed=true\n::error::PRIVATE_SENTINEL',
                     'site_changed<<EOF\ntrue\nEOF'):
            path = self.root / 'metadata'; path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                b.relay(path, self.output)
        self.assertFalse(self.output.exists())

    def test_revision_is_not_forwarded_and_public_values_are_typed(self):
        path = self.root / 'metadata'
        path.write_text('code_sha='+'a'*40+'\nsite_changed=true\ndataset_id='+'b'*64+'\n')
        b.relay(path, self.output)
        self.assertNotIn('a'*40, self.output.read_text())
        self.assertIn('site_changed=true', self.output.read_text())

    def test_pipeline_targeted_flag_reaches_workflow_condition(self):
        # The pipeline emits a boolean indicating a targeted run, not a CIK.
        # Reproduce the ordinary-update output that previously rejected a run.
        for targeted in ('false', 'true'):
            with self.subTest(targeted=targeted):
                self.output.unlink(missing_ok=True)
                command = ('echo "migration_only=false" >> "$GITHUB_OUTPUT"; '
                           f'echo "targeted_cik={targeted}" >> "$GITHUB_OUTPUT"')
                (self.specs / 'fixture.job.0.json').write_text(json.dumps({
                    'run': command, 'relay-output': True,
                    'output-keys': ['migration_only', 'targeted_cik']}))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(b.execute(self.root, 'fixture.job.0', self.env), 0)
                self.assertEqual(self.output.read_text(),
                                 f'migration_only=false\ntargeted_cik={targeted}\n')

    def test_pipeline_targeted_flag_rejects_nonboolean_metadata(self):
        path = self.root / 'metadata'
        for value in ('', '320193', '1', 'False', 'PRIVATE_SENTINEL'):
            path.write_text(f'migration_only=false\ntargeted_cik={value}\n')
            with self.subTest(value=value), self.assertRaises(ValueError):
                b.relay(path, self.output, keys=['migration_only', 'targeted_cik'])
            self.assertFalse(self.output.exists())

    def test_only_bounded_temporary_paths_reach_environment(self):
        path = self.root / 'metadata'
        path.write_text('ARTIFACT_DIR=/etc/private\n')
        with self.assertRaises(ValueError):
            b.relay(path, self.environment, environment=True, env=self.env)

    def test_debug_and_branch_guards_fail_before_execution(self):
        self.spec('touch should-not-exist')
        for values in ({'RUNNER_DEBUG':'1'}, {'ACTIONS_STEP_DEBUG':'true'}, {'GITHUB_REF':'refs/pull/1/merge'}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                b.execute(self.root, 'fixture.job.0', self.env | values)
        self.assertFalse((self.root / 'should-not-exist').exists())

    def test_main_never_prints_private_exception_details(self):
        result = subprocess.run([sys.executable, b.__file__, '--root', str(self.root), '--step', 'fixture.job.999'],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        self.assertNotIn('Traceback', result.stdout + result.stderr)

    def test_pin_roundtrip_rejects_tamper_wrong_run_and_wrong_repository(self):
        key = b.quiet(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048']).decode()
        env = self.env | {'SIS_PIN_PRIVATE_KEY':key, 'GITHUB_RUN_ID':'123',
                         'SIS_IMPLEMENTATION_REPOSITORY':'wesley-yon/super-investor-seeker-migration'}
        raw = b.pin_message(env, 'a'*40)
        pin = b.base64.urlsafe_b64encode(b.crypt_pin(raw, key)).decode()
        self.assertEqual(b.unseal(env, pin), 'a'*40)
        self.assertNotIn('a'*40, pin)
        for changed in (env | {'GITHUB_RUN_ID':'124'}, env | {'SIS_IMPLEMENTATION_REPOSITORY':'wesley-yon/super-investor-seeker'}):
            with self.assertRaises(ValueError):
                b.unseal(changed, pin)
        with self.assertRaises(ValueError):
            b.unseal(env, ('A' if pin[0] != 'A' else 'B') + pin[1:])

    def test_git_token_is_ephemeral_not_an_argument_or_config_write(self):
        env = b.authorize_git({'SIS_CODE_READ_TOKEN':'private-credential'})
        self.assertNotIn('SIS_CODE_READ_TOKEN', env)
        self.assertEqual(env['GIT_CONFIG_COUNT'], '1')
        self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')

    def test_private_diagnostics_redact_credentials_and_isolate_other_runner_files(self):
        self.spec('echo "$TEST_SECRET"; echo "unsafe" >> "$GITHUB_PATH"; echo "unsafe" >> "$GITHUB_STATE"')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.execute(self.root, 'fixture.job.0', self.env | {'TEST_SECRET':'secret-12345678'}), 0)
        self.assertEqual((self.root / 'private-step-logs/test/fixture.job.0.log').read_text(), '[REDACTED]\n')

    def test_incidental_test_metadata_stays_private_without_an_explicit_contract(self):
        self.spec('echo "unused_private_field=PRIVATE_SENTINEL" >> "$GITHUB_OUTPUT"')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.execute(self.root, 'fixture.job.0', self.env), 0)
        self.assertFalse(self.output.exists())
        path = self.specs / 'fixture.job.0.json'
        spec = json.loads(path.read_text()); spec['relay-output'] = True
        path.write_text(json.dumps(spec))
        with self.assertRaises(ValueError):
            b.execute(self.root, 'fixture.job.0', self.env)


if __name__ == '__main__':
    unittest.main()
