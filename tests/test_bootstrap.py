import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

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
        # These tests isolate the log boundary; ApprovalTests below exercise
        # actual Git checkouts and the approval gate without mocking it.
        verify = patch.object(b, 'verify_checkout', return_value='a'*40)
        spec = patch.object(b, 'read_spec', side_effect=lambda root, key:
                            json.loads((root / '.private-workflow-steps' / (key + '.json')).read_text()))
        verify.start(); spec.start()
        self.addCleanup(verify.stop); self.addCleanup(spec.stop)

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

    def test_daily_insider_manifest_reaches_build_only_as_exact_sha256(self):
        digest = 'b' * 64
        self.spec('echo "insider_manifest_sha256=' + digest + '" >> "$GITHUB_OUTPUT"')
        path = self.specs / 'fixture.job.0.json'
        spec = json.loads(path.read_text())
        spec.update({'relay-output': True, 'output-keys': ['insider_manifest_sha256']})
        path.write_text(json.dumps(spec))
        self.assertEqual(b.execute(self.root, 'fixture.job.0', self.env), 0)
        self.assertEqual(self.output.read_text(), 'insider_manifest_sha256=' + digest + '\n')
        self.output.unlink()
        for value in ('private-value', 'b' * 40, 'b' * 65, 'B' * 64):
            source = self.root / 'invalid'; source.write_text('insider_manifest_sha256=' + value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                b.relay(source, self.output, keys=['insider_manifest_sha256'])
            self.assertFalse(self.output.exists())

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


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.root = self.folder / 'implementation'; self.root.mkdir()
        self.repo = 'wesley-yon/super-investor-seeker'
        self.env = dict(os.environ, SIS_IMPLEMENTATION_REPOSITORY=self.repo,
                        GITHUB_REF='refs/heads/main', GITHUB_RUN_ID='42',
                        GITHUB_OUTPUT=str(self.folder / 'output'), RUNNER_TEMP=str(self.folder),
                        GITHUB_JOB='approval-test')
        for name in ('RUNNER_DEBUG', 'ACTIONS_STEP_DEBUG', 'ACTIONS_RUNNER_DEBUG', 'SIS_IMPLEMENTATION_PIN'):
            self.env.pop(name, None)
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Approval fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        specs = self.root / '.private-workflow-steps'; specs.mkdir()
        (specs / 'fixture.job.0.json').write_text(json.dumps({'run': 'echo approved > executed'}))
        self.git('add', '.'); self.git('commit', '--quiet', '-m', 'Approved fixture')
        self.sha = self.git('rev-parse', 'HEAD').strip()
        self.policy = self.folder / 'implementation-approval.json'
        self.policy.write_text(json.dumps(b.approval_record(self.repo, self.sha)))
        patched = patch.object(b, 'APPROVAL_PATH', self.policy); patched.start()
        self.addCleanup(patched.stop)

    def git(self, *arguments):
        return subprocess.check_output(['git', '-C', str(self.root), *arguments], text=True)

    def test_approved_checkout_executes_but_unapproved_commit_cannot(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.execute(self.root, 'fixture.job.0', self.env), 0)
        self.assertEqual((self.root / 'executed').read_text(), 'approved\n')
        (self.root / 'executed').unlink()
        self.git('commit', '--quiet', '--allow-empty', '-m', 'Unreviewed revision')
        with self.assertRaisesRegex(ValueError, 'not approved'):
            b.execute(self.root, 'fixture.job.0', self.env)
        self.assertFalse((self.root / 'executed').exists())

    def test_dirty_checkout_and_untracked_spec_cannot_execute(self):
        spec = self.root / '.private-workflow-steps/fixture.job.0.json'
        spec.write_text(json.dumps({'run': 'touch executed'}))
        with self.assertRaisesRegex(ValueError, 'tracked modifications'):
            b.execute(self.root, 'fixture.job.0', self.env)
        self.git('restore', '.')
        (spec.parent / 'untracked.job.0.json').write_text(json.dumps({'run': 'touch executed'}))
        with self.assertRaises(ValueError):
            b.execute(self.root, 'untracked.job.0', self.env)
        self.assertFalse((self.root / 'executed').exists())

    def test_missing_unconfigured_tampered_and_symlink_policy_fail_closed(self):
        original = self.policy.read_text()
        for record in ({'version': 1, 'repository': self.repo, 'ref': '', 'commit_sha256': ''},
                       json.loads(original) | {'ref': 'refs/heads/main'},
                       json.loads(original) | {'repository': 'attacker/repo'}):
            self.policy.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                b.verify_checkout(self.root, self.env)
        self.policy.unlink()
        with self.assertRaises(FileNotFoundError):
            b.verify_checkout(self.root, self.env)
        target = self.folder / 'other.json'; target.write_text(original)
        self.policy.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            b.verify_checkout(self.root, self.env)

    def test_digest_binds_repository_and_commit_without_publishing_sha(self):
        record = b.approval_record(self.repo, self.sha)
        self.assertNotIn(self.sha, json.dumps(record))
        self.assertNotEqual(record['commit_sha256'], b.revision_digest(self.repo + '-migration', self.sha))
        self.assertEqual(b.verify_checkout(self.root, self.env | {'SIS_APPROVED_SHA': 'b'*40}), self.sha)

    def test_resolver_uses_approved_tag_and_rejects_moved_tag(self):
        env = self.env | {'SIS_CODE_READ_TOKEN': 'fixture-read-token', 'SIS_PIN_PRIVATE_KEY': 'fixture-key'}
        for sha in (self.sha, 'b'*40):
            with self.subTest(sha=sha), patch.object(b.urllib.request, 'urlopen') as request, patch.object(b, 'crypt_pin', return_value=b'sealed'):
                request.return_value.__enter__.return_value = io.StringIO(json.dumps({'sha': sha}))
                if sha == self.sha:
                    with contextlib.redirect_stdout(io.StringIO()):
                        b.resolve(env)
                else:
                    with self.assertRaisesRegex(ValueError, 'not approved'):
                        b.resolve(env)
                self.assertTrue(request.call_args.args[0].full_url.endswith(
                    '/commits/' + json.loads(self.policy.read_text())['ref'].removeprefix('refs/tags/')))

    def test_existing_sealed_target_is_rechecked_before_resolve_or_fetch(self):
        env = self.env | {'SIS_IMPLEMENTATION_PIN': 'fixture-sealed-pin'}
        with patch.object(b, 'unseal', return_value='b'*40), patch.object(b, 'authorize_git') as credentials:
            with self.assertRaisesRegex(ValueError, 'not approved'):
                b.resolve(env)
            with self.assertRaisesRegex(ValueError, 'not approved'):
                b.fetch(self.folder / 'rejected-checkout', env)
            credentials.assert_not_called()
        self.assertFalse((self.folder / 'rejected-checkout').exists())

    def test_approved_sealed_target_fetches_exact_commit_without_persisted_credentials(self):
        key = b.quiet(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048']).decode()
        env = self.env | {'SIS_PIN_PRIVATE_KEY': key, 'SIS_CODE_READ_TOKEN': 'read-fixture-credential'}
        pin = b.base64.urlsafe_b64encode(b.crypt_pin(b.pin_message(env, self.sha), key)).decode()
        target = self.folder / 'fetched'
        quiet = b.quiet

        def local_origin(arguments, **kwargs):
            # Only replace the network origin; all transport, pin, Git and
            # checkout verification code executes against a real repository.
            if arguments[3:6] == ['remote', 'add', 'origin']:
                arguments = [*arguments[:-1], str(self.root)]
            return quiet(arguments, **kwargs)

        result = io.StringIO()
        with patch.object(b, 'quiet', side_effect=local_origin), contextlib.redirect_stdout(result):
            b.fetch(target, env | {'SIS_IMPLEMENTATION_PIN': pin})
            self.assertEqual(b.execute(target, 'fixture.job.0', self.env), 0)
        self.assertEqual(b.verify_checkout(target, self.env), self.sha)
        self.assertEqual((target / 'executed').read_text(), 'approved\n')
        self.assertNotIn(self.sha, result.getvalue())
        self.assertNotIn('read-fixture-credential', (target / '.git/config').read_text())


if __name__ == '__main__':
    unittest.main()
