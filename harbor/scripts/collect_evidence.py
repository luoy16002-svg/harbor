"""Copy only known public-fixture results and clean UI renders into a release."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import sys
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
package = Path(sys.argv[1]).resolve()
output = package / 'docs/evidence'
output.mkdir(parents=True, exist_ok=True)
sources = {
    'test-suite.json': root / '.cache/test-suite.json',
    'control-plane.json': root / '.cache/control-plane/results.json',
    'connection-quality.json': root / '.cache/connection-quality.json',
    'network-preservation.json': root / '.cache/network-baseline/result.json',
    'network-session-context.json': root / '.cache/network-baseline/session-context.json',
    'interop.json': root / '.cache/interop/results.json',
    'dependency-advisories.json': root / '.cache/dependency-advisories.json',
    'nuget-advisories.json': root / '.cache/nuget-advisories.json',
    'native-recovery.json': root / '.cache/native-recovery/result.json',
    'native-tun.json': root / '.cache/native-tun/result.json',
    'visual-check.json': root / '.cache/visual-final/visual-check.json',
    'live-line-verification.json': root / '.cache/selected-line-check.json',
    'live-proxy.json': root / '.cache/selected-normal-check.json',
    'live-direct-exceptions.json': root / '.cache/live-exceptions.json',
}
for name, source in sources.items():
    (output / name).unlink(missing_ok=True)
    if source.is_file():
        report = json.loads(source.read_text(encoding='utf-8-sig'))
        if name == 'dependency-advisories.json' and report.get('cargoLockSha256') != hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest():
            print(f'Skipping {name}: dependency lockfile changed.'); continue
        if name == 'nuget-advisories.json' and report.get('projectSha256') != hashlib.sha256((root / 'desktop/Harbor.csproj').read_bytes()).hexdigest():
            print(f'Skipping {name}: desktop dependencies changed.'); continue
        key = 'engineSha256' if name in {'interop.json', 'native-tun.json', 'control-plane.json', 'connection-quality.json', 'test-suite.json', 'network-preservation.json', 'network-session-context.json', 'live-line-verification.json', 'live-proxy.json', 'live-direct-exceptions.json'} else 'applicationSha256'
        binary = 'harbor-engine.exe' if key == 'engineSha256' else 'Harbor.dll'
        if name not in {'dependency-advisories.json', 'nuget-advisories.json'} and report.get(key) != hashlib.sha256((package / binary).read_bytes()).hexdigest():
            print(f'Skipping {name}: not recorded against this binary.')
            continue
        if name == 'test-suite.json' and report.get('applicationSha256') != hashlib.sha256((package / 'Harbor.dll').read_bytes()).hexdigest():
            print('Skipping test suite: desktop assembly changed.'); continue
        if name in {'live-line-verification.json', 'live-proxy.json', 'live-direct-exceptions.json'}:
            # User configuration stays private even if a future diagnostic adds fields.
            summary = {key: report[key] for key in ['checkedAt', 'engineSha256', 'isolated', 'preflightPassed', 'passed', 'status', 'elapsedMs', 'verified', 'systemSettingsModified', 'uploaded', 'downloaded', 'failedFlows'] if key in report}
            summary['successfulHttpsRequests'] = sum(item.get('passed') is True and item.get('status') == 200 for item in report.get('requests', []))
            if name == 'live-direct-exceptions.json':
                summary.update({key: report[key] for key in ['savedDnsUsed', 'routingMode', 'bilibiliFlowDirect', 'workFlowProxied', 'gameDomainDirect', 'liveGameSessionTested'] if key in report})
                summary['successfulHttpsResponses'] = sum(item.get('passed') is True for item in report.get('requests', []))
            (output / name).write_text(json.dumps(summary, indent=2), encoding='utf-8')
        else:
            shutil.copyfile(source, output / name)
visual = root / '.cache/visual-final'
for name in ['overview-1280.png', 'overview-980.png', 'overview-live.png', 'overview-live-980.png',
             'overview-configured.png', 'nodes-configured.png', 'nodes-batch-1280.png', 'nodes-batch-980.png', 'routing-configured.png', 'dns-configured.png',
             'overview-routing-1280.png', 'overview-routing-980.png', 'routing-modes-1280.png', 'routing-modes-980.png', 'routing-direct-980.png',
             'direct-exceptions-editor.png', 'direct-exceptions-editor-620.png', 'routing-exceptions-1280.png', 'routing-exceptions-980.png',
             'workspace-history-preview.png', 'workspace-history-preview-660.png', 'workspace-history-unavailable.png', 'settings-history-1280.png', 'settings-history-980.png',
             'diagnostics-live-1280.png', 'diagnostics-live-980.png', 'dns-live-1280.png', 'dns-live-980.png',
             'connections-live.png', 'nodes.png', 'subscriptions.png', 'subscriptions-configured-1280.png', 'subscriptions-configured-980.png',
             'subscriptions-downloading-1280.png', 'subscription-update-preview.png', 'subscription-update-preview-640.png', 'privacy.png', 'routing-scrolled.png',
             'dns.png', 'settings.png', 'node-editor.png', 'group-editor.png', 'import-preview.png']:
    (output / name).unlink(missing_ok=True)
    if (visual / name).is_file() and (output / 'visual-check.json').is_file():
        shutil.copyfile(visual / name, output / name)
files = ['Harbor.exe', 'Harbor.dll', 'harbor-engine.exe', 'wintun.dll']
manifest = {
    'assembledAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'version': ET.parse(root / 'desktop/Harbor.csproj').findtext('./PropertyGroup/Version'), 'platform': 'win-x64', 'runtime': '.NET 9.0.19',
    'cargoLockSha256': hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest(),
    'nativeNetworkValidation': {name: 'evidence provided' if (output / name).is_file() else 'not run for this binary' for name in ['native-recovery.json', 'native-tun.json']},
    'files': {name: hashlib.sha256((package / name).read_bytes()).hexdigest() for name in files},
    'note': 'Short local checks and UI renders; see verification.md for unverified capabilities.',
}
(output / 'build.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(f'Collected public fixture evidence in {output.relative_to(package)}')
