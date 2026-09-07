"""Check public dependency names/versions; no source, configuration or credentials are sent."""
from pathlib import Path
import datetime,hashlib,json,tomllib,urllib.request
root=Path(__file__).resolve().parents[1]
packages=[p for p in tomllib.loads((root/'Cargo.lock').read_text(encoding='utf-8'))['package'] if p.get('source','').startswith('registry+') or p['name']=='smoltcp']
query={'queries':[{'package':{'ecosystem':'crates.io','name':p['name']},'version':p['version']} for p in packages]}
request=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps(query).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=35) as response:results=json.load(response)['results']
if len(results)!=len(packages):raise RuntimeError('Incomplete advisory response')
findings=[dict(package=p['name'],version=p['version'],advisories=r['vulns']) for p,r in zip(packages,results) if r.get('vulns')]
report=dict(checkedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),cargoLockSha256=hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest(),packages=len(packages),findings=findings,source='https://api.osv.dev/v1/querybatch')
(root/'.cache').mkdir(exist_ok=True);(root/'.cache/dependency-advisories.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report));raise SystemExit(bool(findings))
