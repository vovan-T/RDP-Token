"""Static syntax / accidental deployment-data checks. Not a complete secret scanner."""
import ast
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
errors = []
for name in filter(None, files):
    path = root / name
    parts = path.relative_to(root).parts
    if path.is_symlink():
        errors.append(f'{name}: symbolic link requires review')
        continue
    if path.suffix.lower() in {'.p12', '.pfx', '.key', '.pem', '.db', '.sqlite', '.log', '.pcap', '.exe', '.dll', '.msi'}:
        errors.append(f'{name}: deployment or binary file must not be distributed')
    if '.env' in parts or 'work' in parts or 'backups' in parts:
        errors.append(f'{name}: runtime data path')
    if path.suffix.lower() in {'.png', '.ico'}:
        continue
    try:
        content = path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        errors.append(f'{name}: unexpected binary file')
        continue
    if path.suffix == '.py':
        ast.parse(content, filename=name)
    if re.search(r'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/]{40,}', content):
        errors.append(f'{name}: embedded private key')
    if re.search(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b', content):
        errors.append(f'{name}: possible GitHub credential')
if errors:
    print('\n'.join(errors))
    sys.exit(1)
print(f'PASS: reviewed tracked paths and Python syntax ({len([x for x in files if x])} files)')
