"""Collect upstream notices from the pinned Cargo graph and vendored notice files."""
from pathlib import Path
import json
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
output = Path(sys.argv[1]).resolve() / 'licenses'
output.mkdir(parents=True, exist_ok=True)
metadata = json.loads(subprocess.run(
    ['cargo', 'metadata', '--locked', '--filter-platform', 'x86_64-pc-windows-msvc',
     '--format-version', '1'], cwd=ROOT, check=True, capture_output=True,
    encoding='utf-8').stdout)
entries = []
fallbacks = {
    'asn1-rs-impl': ['asn1-rs-LICENSE-MIT', 'asn1-rs-LICENSE-APACHE'],
    'c2rust-bitfields': ['c2rust-LICENSE'],
    'c2rust-bitfields-derive': ['c2rust-LICENSE'],
    'defmt-parser': ['defmt-LICENSE-MIT', 'defmt-LICENSE-APACHE'],
}
for package in metadata['packages']:
    if package['name'] == 'harbor-engine':
        continue
    source = Path(package['manifest_path']).parent
    destination = output / f"{package['name']}-{package['version']}"
    notices = [file for file in source.rglob('*') if file.is_file()
               and file.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE'))]
    saved = []
    for file in notices:
        target = destination / file.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)
        saved.append(target.relative_to(output).as_posix())
    for name in fallbacks.get(package['name'], []) if not notices else []:
        file = ROOT / 'vendor/notices' / name
        if not file.is_file():
            raise RuntimeError(f'Missing upstream notice: {name}')
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, destination / name)
        saved.append((destination / name).relative_to(output).as_posix())
    if not saved:
        raise RuntimeError(f"No license text for {package['name']} {package['version']}")
    entries.append({'name': package['name'], 'version': package['version'],
                    'license': package['license'], 'repository': package['repository'],
                    'notices': sorted(saved)})
for file in (ROOT / 'vendor/notices').iterdir():
    if file.is_file():
        shutil.copyfile(file, output / file.name)
shutil.copyfile(ROOT / 'vendor/wintun/LICENSE.txt', output / 'Wintun.txt')
(output / 'Rust-dependencies.json').write_text(
    json.dumps(entries, indent=2, ensure_ascii=False), encoding='utf-8')
print(f'Collected license notices for {len(entries)} Rust packages and redistributed runtimes.')
