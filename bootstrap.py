"""Credential-safe public transport and log boundary; no application logic."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

SHA = r"[0-9a-f]{40}"
DIGEST = r"[0-9a-f]{64}"
BOOLEAN = r"true|false"
APPROVAL_PATH = Path(__file__).resolve().parent / 'implementation-approval.json'
METADATA = {
    'release_tag': r'dataset-[A-Za-z0-9._-]+',
    'resolved_latest_release_tag': r'dataset-[A-Za-z0-9._-]+',
    'active_tag': r'dataset-[A-Za-z0-9._-]+',
    'dataset_id': DIGEST, 'deployment_id': r'[0-9]+',
    'deploy_needed': BOOLEAN, 'allow_older_release': BOOLEAN,
    'present': BOOLEAN, 'outputs_rebuilt': BOOLEAN, 'legacy_snapshot': BOOLEAN,
    'migration_only': BOOLEAN, 'run_update': BOOLEAN, 'targeted_cik': BOOLEAN,
    'snapshot_changed': BOOLEAN, 'site_changed': BOOLEAN,
    'prepared_sha256': DIGEST, 'processed_accessions': r'[0-9]{1,10}',
    'remaining_due': r'[0-9]{1,10}',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def quiet(args, *, env=None, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, check=False)
    require(result.returncode == 0, 'Private subprocess failed')
    return result.stdout


def safe_mode(env):
    require(env.get('RUNNER_DEBUG', '0') != '1'
            and env.get('ACTIONS_STEP_DEBUG', 'false').lower() != 'true'
            and env.get('ACTIONS_RUNNER_DEBUG', 'false').lower() != 'true',
            'Private execution forbids debug logging')
    require(env.get('GITHUB_REF', 'refs/heads/main') == 'refs/heads/main', 'Main branch required')


def repository(env):
    value = env['SIS_IMPLEMENTATION_REPOSITORY']
    require(value in {'wesley-yon/super-investor-seeker',
                      'wesley-yon/super-investor-seeker-migration'}, 'Unexpected implementation repository')
    return value


def revision_digest(repo, sha):
    require(re.fullmatch(SHA, sha), 'Invalid implementation identity')
    return hashlib.sha256(f'publisher-approval-v1\n{repo}\n{sha}\n'.encode()).hexdigest()


def approval_record(repo, sha):
    digest = revision_digest(repo, sha)
    return {'version': 1, 'repository': repo,
            'ref': 'refs/tags/publisher-approved-' + digest[:24], 'commit_sha256': digest}


def validate_approval(record, repo, *, require_configured=True):
    require(isinstance(record, dict) and set(record) == {'version', 'repository', 'ref', 'commit_sha256'},
            'Invalid approval record')
    require(type(record['version']) is int and record['version'] == 1
            and record['repository'] == repo, 'Approval repository mismatch')
    if not require_configured and record['ref'] == record['commit_sha256'] == '':
        return record
    digest = record['commit_sha256']
    require(isinstance(digest, str) and re.fullmatch(DIGEST, digest), 'Approval is not configured')
    require(record['ref'] == 'refs/tags/publisher-approved-' + digest[:24], 'Invalid approved reference')
    return record


def approved(env, sha=None):
    # This file belongs to the checked-out protected PUBLIC publisher revision.
    # Private code, repository variables and workflow inputs cannot override it.
    require(not APPROVAL_PATH.is_symlink(), 'Approval symlink forbidden')
    record = validate_approval(json.loads(APPROVAL_PATH.read_text()), repository(env))
    if sha is not None:
        require(revision_digest(repository(env), sha) == record['commit_sha256'],
                'Implementation revision is not approved')
    return record


def verify_checkout(root, env):
    safe_mode(env)
    root = Path(root).resolve()
    require(Path(quiet(['git', '-C', str(root), 'rev-parse', '--show-toplevel']).decode().strip()).resolve() == root,
            'Implementation must be the checkout root')
    sha = quiet(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
    approved(env, sha)
    require(not quiet(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=no']),
            'Approved implementation has tracked modifications')
    return sha


def read_spec(root, key):
    # Read the approved commit's blob, never an untracked replacement file.
    return json.loads(quiet(['git', '-C', str(root), 'show',
                             'HEAD:.private-workflow-steps/' + key + '.json']))


def pin_message(env, sha):
    run = env['GITHUB_RUN_ID']
    require(run.isdecimal() and re.fullmatch(SHA, sha), 'Invalid run identity')
    return f'{run}:{repository(env)}:{sha}'.encode()


def crypt_pin(payload, key, *, decrypt=False):
    # RSA OAEP/SHA256, implemented by OpenSSL, keeps private revisions out of
    # public job metadata. Bind the plaintext to this repository and run below.
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'key.pem'
        path.touch(mode=0o600)
        if decrypt:
            path.write_text(key)
        else:
            path.write_bytes(quiet(['openssl', 'pkey', '-pubout'], data=key.encode()))
        arguments = ['openssl', 'pkeyutl', '-decrypt' if decrypt else '-encrypt',
                     '-inkey', str(path), '-pkeyopt', 'rsa_padding_mode:oaep',
                     '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256']
        if not decrypt:
            arguments += ['-pubin']
        return quiet(arguments, data=payload)


def unseal(env, pin):
    require(re.fullmatch(r'[A-Za-z0-9_-]{300,1500}={0,2}', pin), 'Invalid sealed target')
    raw = crypt_pin(base64.urlsafe_b64decode(pin), env['SIS_PIN_PRIVATE_KEY'], decrypt=True)
    sha = raw.decode().rsplit(':', 1)[-1]
    require(raw == pin_message(env, sha), 'Target belongs to another repository or run')
    return sha


def authorize_git(env):
    result = env.copy()
    token = result.pop('SIS_CODE_READ_TOKEN', '')
    require(token, 'Code read credential required')
    result.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
                  GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + base64.b64encode(('x-access-token:' + token).encode()).decode(),
                  GIT_TERMINAL_PROMPT='0')
    return result


def resolve(env):
    safe_mode(env)
    record = approved(env)
    existing = env.get('SIS_IMPLEMENTATION_PIN', '')
    if existing:
        approved(env, unseal(env, existing))
        pin = existing
    else:
        repo = repository(env)
        ref = record['ref'].removeprefix('refs/tags/')
        request = urllib.request.Request('https://api.github.com/repos/' + repo + '/commits/' + ref,
                    headers={'Authorization': 'Bearer ' + env['SIS_CODE_READ_TOKEN'],
                             'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            sha = json.load(response)['sha']
        approved(env, sha)
        pin = base64.urlsafe_b64encode(crypt_pin(pin_message(env, sha), env['SIS_PIN_PRIVATE_KEY'])).decode()
    with Path(env['GITHUB_OUTPUT']).open('a') as stream:
        stream.write('pin=' + pin + '\n')
    print('Trusted implementation target pinned.')


def fetch(root, env):
    safe_mode(env)
    sha = unseal(env, env['SIS_IMPLEMENTATION_PIN'])
    approved(env, sha)
    root = Path(root).resolve()
    require(not root.exists(), 'Private checkout already exists')
    root.mkdir(parents=True, mode=0o700)
    child = authorize_git(env)
    child.pop('SIS_PIN_PRIVATE_KEY', None)
    quiet(['git', 'init', '--quiet', str(root)], env=child)
    quiet(['git', '-C', str(root), 'remote', 'add', 'origin',
           'https://github.com/' + repository(env) + '.git'], env=child)
    quiet(['git', '-C', str(root), 'fetch', '--quiet', '--no-tags', '--depth=1', 'origin', sha], env=child)
    quiet(['git', '-C', str(root), 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], env=child)
    require(quiet(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip() == sha,
            'Checkout identity mismatch')
    config = quiet(['git', '-C', str(root), 'config', '--local', '--list']).decode()
    require('extraheader' not in config.lower() and 'x-access-token' not in config.lower(), 'Persisted credential')
    verify_checkout(root, env)
    print('Pinned implementation fetched.')


def relay(source, target, *, environment=False, env=None, keys=None):
    if not source.exists() or not target:
        return
    text = source.read_text()
    require(len(text) <= 100_000, 'Oversized runner metadata')
    accepted = []
    for line in text.splitlines():
        require('=' in line, 'Multiline metadata is forbidden')
        key, value = line.split('=', 1)
        if keys is not None and key not in keys:
            continue
        if key == 'code_sha':
            require(re.fullmatch(SHA, value), 'Invalid private revision')
            continue  # Private identity stays inside the checkout and receipt.
        if environment:
            require(key in {'ARTIFACT_DIR', 'CANDIDATE_DIR'}, 'Unapproved runner environment')
            path = Path(value).resolve()
            require(path.is_relative_to(Path((env or os.environ)['RUNNER_TEMP']).resolve())
                    and '\n' not in value and re.fullmatch(r'[A-Za-z0-9_./-]+', value), 'Invalid temporary path')
        else:
            require(key in METADATA and re.fullmatch(METADATA[key], value), 'Unapproved public metadata')
        accepted.append(line)
    if not accepted:
        return
    with Path(target).open('a') as out:
        out.write('\n'.join(accepted) + ('\n' if accepted else ''))


def execute(root, key, env=None):
    env = dict(os.environ if env is None else env)
    safe_mode(env)
    require(re.fullmatch(r'[a-z0-9_-]+\.[a-z0-9_-]+\.[0-9]+', key), 'Invalid step identity')
    root = Path(root).resolve()
    verified_sha = verify_checkout(root, env)
    spec = read_spec(root, key)
    require('${{' not in spec['run'], 'Unresolved workflow expression')
    job = env.get('GITHUB_JOB', 'local')
    require(re.fullmatch(r'[A-Za-z0-9_-]+', job), 'Invalid job identity')
    logs = Path(env.get('RUNNER_TEMP', str(root / '.private-run'))) / 'private-step-logs' / job
    logs.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = {name: logs / (key + '.' + name) for name in ('output', 'environment', 'summary', 'log', 'path', 'state')}
    for path in paths.values():
        path.write_text(''); path.chmod(0o600)
    child = env.copy()
    child.pop('SIS_PIN_PRIVATE_KEY', None)
    child.update(GITHUB_WORKSPACE=str(root), GITHUB_OUTPUT=str(paths['output']),
                 GITHUB_ENV=str(paths['environment']), GITHUB_STEP_SUMMARY=str(paths['summary']),
                 GITHUB_PATH=str(paths['path']), GITHUB_STATE=str(paths['state']))
    if child.get('SIS_CODE_READ_TOKEN'):
        child = authorize_git(child)
    if (root / '.git').exists():
        child['EXPECTED_CODE_SHA'] = verified_sha
        child['REQUESTED_CODE_SHA'] = verified_sha if env.get('SIS_EXPLICIT_PIN') == 'true' else ''
    relative = spec.get('working-directory', '.')
    cwd = (root / relative).resolve()
    require(cwd == root or root in cwd.parents, 'Working directory escape')
    with paths['log'].open('wb') as stream:
        process = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', spec['run']],
                                 cwd=cwd, env=child, stdout=stream, stderr=subprocess.STDOUT)
    # Private diagnostic archives should not retain live credentials either.
    credentials = {value.encode() for name, value in child.items()
                   if value and len(value) >= 8 and re.search(r'TOKEN|SECRET|PASSWORD|PRIVATE_KEY|GIT_CONFIG_VALUE', name)}
    credentials |= {base64.b64encode(b'x-access-token:' + value) for value in credentials}
    for path in paths.values():
        raw = path.read_bytes()
        for value in sorted(credentials, key=len, reverse=True):
            raw = raw.replace(value, b'[REDACTED]')
        path.write_bytes(raw)
    receipt = {'step': key, 'exit_code': process.returncode,
               'log_sha256': hashlib.sha256(paths['log'].read_bytes()).hexdigest()}
    (logs / (key + '.receipt.json')).write_text(json.dumps(receipt, sort_keys=True) + '\n')
    if spec.get('relay-output', False):
        relay(paths['output'], env.get('GITHUB_OUTPUT'), env=env, keys=spec.get('output-keys'))
    if spec.get('relay-environment', False):
        relay(paths['environment'], env.get('GITHUB_ENV'), environment=True, env=env)
    print('Private step passed.' if process.returncode == 0 else 'Private step failed; details retained privately.')
    return process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('resolve', 'fetch', 'verify', 'execute'), default='execute')
    parser.add_argument('--root')
    parser.add_argument('--step')
    args = parser.parse_args()
    try:
        if args.mode == 'resolve':
            resolve(os.environ)
        elif args.mode == 'fetch':
            fetch(args.root, os.environ)
        elif args.mode == 'verify':
            verify_checkout(args.root, os.environ)
        else:
            return execute(args.root, args.step)
        return 0
    except Exception:
        print('Private adapter rejected this operation; no private output was published.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
