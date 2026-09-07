"""Explicit source allowlist; never include local credentials, test CAs, caches or other projects."""
from pathlib import Path
import hashlib,json,zipfile,datetime,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1];dist=root/'dist'
version=ET.parse(root/'desktop/Harbor.csproj').findtext('./PropertyGroup/Version')
package=dist/f'Harbor-{version}-win-x64'
assert (package/'Harbor.exe').is_file() and (package/'harbor-engine.exe').is_file() and (package/'wintun.dll').is_file()
def archive(path,files,prefix):
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED,compresslevel=7) as output:
        for file,relative in sorted(files,key=lambda pair:str(pair[1])):output.write(file,str(Path(prefix)/relative))
def current_release_file(path):
    if not path.is_file(): return False
    relative=path.relative_to(package)
    # A publish directory can contain stale documentation from an earlier build.
    # Ship current source docs and separately assembled evidence only.
    return relative.parts[0]!='docs' or relative.parts[:2]==('docs','evidence') or (root/relative).is_file()
archive(dist/f'Harbor-{version}-win-x64.zip',[(p,p.relative_to(package)) for p in package.rglob('*') if current_release_file(p)],package.name)
files=[]
for name in ['Cargo.toml','Cargo.lock','README.md','LICENSE','THIRD-PARTY.md','.gitignore']:
    file=root/name;assert file.is_file();files.append((file,Path(name)))
for folder in ['engine','desktop','tests','scripts','docs','.cargo','vendor']:
    for file in (root/folder).rglob('*'):
        if not file.is_file():continue
        relative=file.relative_to(root)
        if any(part in {'bin','obj','target','.git','__pycache__','.cache'} for part in relative.parts):continue
        if file.name == '.cargo-ok':continue
        if file.suffix.lower() in {'.dll','.exe','.pdb','.user','.pyc','.log','.dat','.key','.pem','.pfx','.p12','.zip','.bundle'}:continue
        files.append((file,relative))
archive(dist/f'Harbor-{version}-source.zip',files,'Harbor-source')
manifest={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [dist/f'Harbor-{version}-win-x64.zip',dist/f'Harbor-{version}-source.zip']}
(dist/'SHA256.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8');print(json.dumps(manifest,indent=2))
