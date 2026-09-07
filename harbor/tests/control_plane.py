"""Exercise IPC rejection/atomicity with isolated loopback listeners. No system capture."""
from pathlib import Path
import copy, datetime, hashlib, json, os, queue, socket, struct, subprocess, threading

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.cache/control-plane'
OUT.mkdir(parents=True, exist_ok=True)
ENGINE = Path(os.environ.get('HARBOR_TEST_ENGINE', ROOT / 'target/debug/harbor-engine.exe')).resolve()
results = []

def check(name, action):
    action()
    results.append(dict(name=name, passed=True))
    print('PASS', name, flush=True)

def require(condition):
    if not condition: raise AssertionError('Control-plane assertion failed')

def available_port():
    for _ in range(20):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1', 0))
            port = tcp.getsockname()[1]
            try: udp.bind(('127.0.0.1', port))
            except OSError: continue
            return port
    raise RuntimeError('Could not allocate a loopback fixture port')

process = subprocess.Popen([str(ENGINE), '--isolated'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding='utf-8',
                           creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
responses = queue.Queue()
threading.Thread(target=lambda: [responses.put(json.loads(line)) for line in process.stdout], daemon=True).start()
next_id = 0

def ask(command, expected=True, **fields):
    global next_id
    next_id += 1
    process.stdin.write(json.dumps(dict(id=next_id, command=command, **fields)) + '\n')
    process.stdin.flush()
    response = responses.get(timeout=8)
    require(response['id'] == next_id and response['ok'] == expected)
    return response.get('result') if expected else response['error']

try:
    config = ask('default_config')
    config.update(listen=f'127.0.0.1:{available_port()}', dnsListen=f'127.0.0.1:{available_port()}',
                  dnsServers=['127.0.0.1:9'], dnsTls=[], rules=[], nodes=[], groups=[], tun=False)
    targets = [dict(host='example.invalid', port=443, protocol='tcp')]
    def isolation():
        candidate = copy.deepcopy(config); candidate['tun'] = True
        require('Isolated' in ask('start', expected=False, config=candidate))
        require(not ask('snapshot')['running'])
        for address in [config['listen'], config['dnsListen']]:
            with socket.socket() as listener: listener.bind(('127.0.0.1', int(address.rsplit(':', 1)[1])))
    check('isolated TUN start rejected before binding listeners', isolation)
    def offline():
        candidate = copy.deepcopy(config); candidate['privacy']['blockDirect'] = True
        report = ask('rehearse', before=config, after=candidate, targets=targets)
        require(report['offline'] and report['networkRequests'] == 0 and not report['healthMeasured'])
        require(report['rows'][0]['before']['outbound'] == 'DIRECT' and report['rows'][0]['after']['outbound'] == 'REJECT')
        require(not ask('snapshot')['running'])
    check('offline route comparison works while stopped', offline)
    def verification_guard():
        require('concrete' in ask('verify', expected=False, config=config, outbound='DIRECT'))
        require(not ask('snapshot')['running'])
    check('single-line verification rejects direct/group targets without starting listeners', verification_guard)
    def dns_preflight():
        candidate = copy.deepcopy(config)
        candidate['nodes'] = [dict(name='local-line', kind='socks5', server='127.0.0.1', port=9)]
        candidate['finalPolicy'] = 'local-line'
        ready = ask('preflight', config=candidate)
        require(ready['ready'] and not ready['dnsRequired'] and not ask('snapshot')['running'])
        for address in [candidate['listen'], candidate['dnsListen']]:
            with socket.socket() as listener: listener.bind(('127.0.0.1', int(address.rsplit(':', 1)[1])))
        with socket.socket(type=socket.SOCK_DGRAM) as upstream:
            upstream.bind(('127.0.0.1', 0)); upstream.settimeout(3)
            def negative_dns():
                for _ in range(2):
                    request, peer = upstream.recvfrom(1024)
                    upstream.sendto(request[:2] + struct.pack('!HHHHH', 0x8183, 1, 0, 0, 0) + request[12:], peer)
            worker = threading.Thread(target=negative_dns, daemon=True); worker.start()
            candidate['dnsServers'] = [f'127.0.0.1:{upstream.getsockname()[1]}']
            candidate['nodes'][0]['server'] = 'missing.fixture.invalid'
            error = ask('preflight', expected=False, config=candidate)
            require('NXDomain' in error and not ask('snapshot')['running'])
            worker.join(timeout=4); require(not worker.is_alive())
    check('DNS preflight needs no listener and preserves negative-answer errors', dns_preflight)
    ask('start', config=config)
    generation = ask('snapshot')['generation']
    def atomic_privacy():
        candidate = copy.deepcopy(config); candidate['privacy']['blockDirect'] = True
        require('stopping Harbor' in ask('configure', expected=False, config=candidate))
        require(ask('snapshot')['generation'] == generation)
        require(ask('explain', host='example.invalid', port=443, protocol='tcp')['outbound'] == 'DIRECT')
    check('privacy routing hot change rejected without applying partial configuration', atomic_privacy)
    def atomic_egress():
        candidate = copy.deepcopy(config); candidate['egressMode'] = 'system' if config.get('egressMode') != 'system' else 'physical'
        require('stopping' in ask('configure', expected=False, config=candidate))
        require(ask('snapshot')['generation'] == generation)
    check('changing upstream routing requires a stop and leaves the running configuration intact', atomic_egress)
    def metadata():
        candidate = copy.deepcopy(config); candidate['privacy'].update(hideMetadata=True, historySecs=0)
        ask('configure', config=candidate)
        require(ask('snapshot')['events'] == [])
        require(ask('clear_history')['cleared'])
    check('metadata hiding and zero retention can be applied live', metadata)
    ask('stop')
    def stopped():
        require(not ask('snapshot')['running'])
        for address in [config['listen'], config['dnsListen']]:
            with socket.socket() as listener: listener.bind(('127.0.0.1', int(address.rsplit(':', 1)[1])))
    check('isolated stop releases both local TCP listeners', stopped)
    def cli():
        for args in [['--validate-tun', '--isolated'], ['--isolated', '--validate-tun'], ['--isolated', '--typo']]:
            result = subprocess.run([str(ENGINE), *args], input='', capture_output=True, text=True, timeout=8,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            require(result.returncode != 0)
    check('native TUN validation cannot bypass isolation through argument order', cli)
    def cancel_verification():
        global next_id
        accepted = threading.Event(); release = threading.Event()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(4)
            def proxy():
                with listener.accept()[0] as stream:
                    stream.settimeout(4); require(stream.recv(1024).startswith(b'CONNECT ')); accepted.set(); release.wait(4)
            worker = threading.Thread(target=proxy, daemon=True); worker.start()
            candidate = copy.deepcopy(config)
            candidate['nodes'] = [dict(name='local-stall', kind='http', server='127.0.0.1', port=listener.getsockname()[1])]
            next_id += 1; verify_id = next_id
            process.stdin.write(json.dumps(dict(id=verify_id, command='verify', config=candidate, outbound='local-stall')) + '\n'); process.stdin.flush()
            try:
                require(accepted.wait(3))
                next_id += 1; stop_id = next_id
                process.stdin.write(json.dumps(dict(id=stop_id, command='stop')) + '\n'); process.stdin.flush()
                replies = [responses.get(timeout=4), responses.get(timeout=4)]
                by_id = {reply['id']: reply for reply in replies}
                require(by_id[stop_id]['ok'] and not by_id[verify_id]['ok'] and 'cancelled' in by_id[verify_id]['error'])
            finally:
                release.set(); worker.join(timeout=5)
        require(not ask('snapshot')['running'])
    check('stop stays responsive and cancels an in-flight line verification', cancel_verification)
    ask('shutdown'); process.wait(timeout=5); require(process.returncode == 0)
    report = dict(checkedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  engineSha256=hashlib.sha256(ENGINE.read_bytes()).hexdigest(), passed=True,
                  isolated=True, systemMutations=False, checks=results)
    (OUT / 'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'{len(results)} control-plane checks passed.')
finally:
    if process.poll() is None: process.kill(); process.wait(timeout=5)
