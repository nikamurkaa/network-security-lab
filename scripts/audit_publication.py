#!/usr/bin/env python3
"""Conservative public artifact check; does not grant publication permission."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
BANNED_NAMES = {'.gns3project', '.image', '.ghost', '.iso', '.vmdk', '.qcow2', '.docx', '.pdf', '.key', '.pem', '.p12'}
BANNED_CONTENT = [re.compile(p, re.I) for p in (
    r'School[\s_-]*21', r'Школ[аы]\s*21', r'CbS[234](?:_|\b)', r'ID_15\d{5}',
    r'BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY', r'\b(?:api[_-]?key|access[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_-]{16,}',
)]


def audit():
    problems = []
    for file in ROOT.rglob('*'):
        if not file.is_file() or any(part in {'.git', 'build', '__pycache__', '.venv'} for part in file.parts):
            continue
        if file.suffix.lower() in BANNED_NAMES:
            problems.append(f'Forbidden file type: {file.relative_to(ROOT)}')
        if file.suffix in {'.md', '.py', '.cfg', '.yml', '.yaml', '.txt', '.json', '.gns3', ''} or file.name in {'Makefile', '.gitignore'}:
            try:
                s = file.read_text(encoding='utf-8')
            except (UnicodeDecodeError, OSError):
                continue
            for pattern in BANNED_CONTENT:
                if pattern.search(s):
                    problems.append(f'Found sensitive/publication term in {file.relative_to(ROOT)}: {pattern.pattern}')
    return problems


if __name__ == '__main__':
    results = audit()
    if results:
        print('\n'.join(results), file=sys.stderr)
        sys.exit(1)
    print('Public-artifact filename/content checks passed (not a license or secret-scanning guarantee).')
