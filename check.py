"""Audit the explicit public tree and the credential boundary of its workflows."""
import json
from pathlib import Path
import re
import subprocess
import sys
import yaml

try:
    from scripts.publisher_bootstrap import validate_approval
except ImportError:
    from bootstrap import validate_approval

WORKFLOWS = {
    'activate-insider-pilot.yml', 'deploy-pages.yml', 'finalize-private-snapshots.yml',
    'keepalive.yml', 'maintain-insider-checkpoint.yml', 'publish-pages.yml',
    'refresh-cusip-registry.yml', 'update-data.yml', 'verify-environment-credentials.yml',
    'verify-insider-checkpoint.yml', 'publisher-checks.yml', 'rollback-pages.yml', 'verify-private-candidate.yml',
}
FILES = {'README.md', 'LICENSE', '.gitignore', 'bootstrap.py', 'check.py',
         'implementation-approval.json', 'requirements.txt', '.github/dependabot.yml',
         'tests/test_bootstrap.py'} | {'.github/workflows/' + name for name in WORKFLOWS}


def audit(root, *, history=False):
    root = Path(root)
    if history:
        paths = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
        paths = {p for p in paths if p}
        commits = subprocess.check_output(['git', '-C', str(root), 'rev-list', '--all'], text=True).splitlines()
        for commit in commits:
            tree = set(subprocess.check_output(['git', '-C', str(root), 'ls-tree', '-r', '--name-only', commit], text=True).splitlines())
            if not tree <= FILES:
                raise ValueError('Unexpected file in public history')
    else:
        paths = {p.relative_to(root).as_posix() for p in root.rglob('*')
                 if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts}
    if paths != FILES:
        raise ValueError('Public tree differs from explicit publisher allowlist')
    for name in paths:
        if (root / name).is_symlink():
            raise ValueError('Public symlink is forbidden')
    validate_approval(json.loads((root / 'implementation-approval.json').read_text()),
                      'wesley-yon/super-investor-seeker', require_configured=history)
    dependencies = yaml.safe_load((root / '.github/dependabot.yml').read_text())
    if dependencies.get('version') != 2 or not any(
            update.get('package-ecosystem') == 'github-actions'
            and update.get('directory') == '/'
            and update.get('schedule', {}).get('interval') == 'weekly'
            for update in dependencies.get('updates', [])):
        raise ValueError('Weekly Actions dependency updates are required')
    for name in WORKFLOWS:
        w = yaml.safe_load((root / '.github/workflows' / name).read_text())
        events = w.get('on', w.get(True, {}))
        if 'pull_request_target' in events:
            raise ValueError('Privileged PR event forbidden')
        is_check = name == 'publisher-checks.yml'
        raw = (root / '.github/workflows' / name).read_text()
        if is_check and any(token in raw for token in ('secrets.', 'private-data', 'github-pages', 'IMPLEMENTATION_READER')):
            raise ValueError('Public checks must have no private access')
        if 'pull_request' in events and not is_check:
            raise ValueError('Private workflow exposed to public pull requests')
        for job in w['jobs'].values():
            if 'steps' not in job:
                continue
            fetched = False
            for step in job['steps']:
                action = step.get('uses', '')
                if action and not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}', action):
                    raise ValueError('Action must be pinned to an exact commit')
                if action.startswith(('actions/cache', 'actions/upload-artifact')):
                    raise ValueError('Private caches and diagnostic artifacts forbidden')
                if action.startswith('actions/checkout') and step.get('with', {}).get('persist-credentials') is not False:
                    raise ValueError('Checkout may persist credentials')
                if action.startswith('actions/checkout') and 'repository' in step.get('with', {}):
                    raise ValueError('Private code must pass through quiet transport')
                if action.startswith('actions/setup-python') and 'cache' in step.get('with', {}):
                    raise ValueError('Dependency cache forbidden for private jobs')
                command = step.get('run', '')
                if '--mode fetch' in command:
                    if step.get('id') != 'verified-implementation':
                        raise ValueError('Verified transport identity required')
                    fetched = True
                if '--step ' in command and not fetched:
                    raise ValueError('Private execution must follow verified transport')
                if 'store_private_workflow_logs.py' in command and (
                        not fetched or '--mode verify' not in command):
                    raise ValueError('Private diagnostics require approval verification')
                if step.get('id', '').endswith('report-writer') and (
                        not fetched or "steps.verified-implementation.outcome == 'success'" not in step.get('if', '')):
                    raise ValueError('Report credential requires verified transport')
                if 'pip install' in command and (
                        '--require-hashes' not in command or '--only-binary=:all:' not in command):
                    raise ValueError('Dependency installs require verified wheel hashes')
    return len(paths)


if __name__ == '__main__':
    count = audit(Path.cwd(), history='--history' in sys.argv)
    print(f'Publisher allowlist passed: {count} files.')
