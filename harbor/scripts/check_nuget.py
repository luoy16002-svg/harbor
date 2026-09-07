"""Record NuGet advisory results for the desktop project without local source paths."""
from pathlib import Path
import datetime, hashlib, json, subprocess

root = Path(__file__).resolve().parents[1]
project = root / 'desktop/Harbor.csproj'
result = subprocess.run(['dotnet', 'list', str(project), 'package', '--vulnerable',
                         '--include-transitive', '--format', 'json'], cwd=root,
                        capture_output=True, text=True, encoding='utf-8', check=True)
value = json.loads(result.stdout)
if value.get('logs') or not value.get('projects'):
    raise RuntimeError('NuGet returned diagnostics or an incomplete project result; review the response.')
findings = []
for item in value['projects']:
    for framework in item.get('frameworks', []):
        for package in framework.get('topLevelPackages', []) + framework.get('transitivePackages', []):
            if package.get('vulnerabilities'): findings.append(package)
report = dict(checkedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
              projectSha256=hashlib.sha256(project.read_bytes()).hexdigest(),
              source='https://api.nuget.org/v3/index.json',
              command='dotnet list package --vulnerable --include-transitive', findings=findings)
(root / '.cache').mkdir(exist_ok=True)
(root / '.cache/nuget-advisories.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report))
raise SystemExit(bool(findings))
