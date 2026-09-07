"""Reproducible local DNS/TCP fault fixtures; optional comparison against a prior engine.

No external DNS, upstream proxy, adapter or operating-system proxy changes are used.
The timing samples measure loopback setup under injected delays, not internet speed.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import math
import os
import queue
import socket
import statistics
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def require(value, message):
    if not value:
        raise AssertionError(message)


def free_port():
    for _ in range(20):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1', 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(('127.0.0.1', port))
                return port
            except OSError:
                pass
    raise RuntimeError('No free loopback fixture port')


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise ConnectionError('Fixture stream closed early')
        result.extend(part)
    return bytes(result)


class Echo(AbstractContextManager):
    def __init__(self, ipv6=False):
        self.socket = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)
        if ipv6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.socket.bind(('::1' if ipv6 else '127.0.0.1', 0))
        self.port = self.socket.getsockname()[1]
        self.socket.listen(128)
        self.socket.settimeout(.1)
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        def transfer(stream):
            with stream:
                stream.settimeout(5)
                try:
                    while data := stream.recv(8192):
                        stream.sendall(data)
                except OSError:
                    pass
        while not self.stop.is_set():
            try:
                stream, _ = self.socket.accept()
                threading.Thread(target=transfer, args=(stream,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def __exit__(self, *args):
        self.stop.set()
        self.socket.close()
        self.worker.join(2)


class Dns(AbstractContextManager):
    def __init__(self, mode):
        self.mode = mode
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.address = f'127.0.0.1:{self.socket.getsockname()[1]}'
        self.socket.settimeout(.1)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.count = 0
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        def respond(request, peer):
            offset = 12
            labels = []
            while request[offset]:
                length = request[offset]
                offset += 1
                labels.append(request[offset:offset + length].decode('ascii'))
                offset += length
            offset += 1
            kind, klass = struct.unpack_from('!HH', request, offset)
            require('.'.join(labels).endswith('.fixture.invalid'), 'Unexpected fixture DNS name')
            require(klass == 1 and kind in (1, 28), 'Unexpected fixture DNS question')
            with self.lock:
                self.count += 1
            delay = 1.2 if self.mode == 'slow-family' and kind == 28 else .2 if self.mode == 'burst' else .001
            if self.mode == 'memory' and kind == 1:
                delay = .1  # Make the first failed IPv6 attempt independent of DNS arrival order.
            if self.stop.wait(delay):
                return
            addresses = (['127.0.0.' + str(index) for index in range(2, 10)] if self.mode == 'many-addresses' else ['127.0.0.1']) if kind == 1 else (
                ['::1'] if self.mode in ('many-addresses', 'memory') else [])
            ttl = 60 if self.mode in ('burst', 'memory') else 0
            response = bytearray(request[:2] + struct.pack('!HHHHH', 0x8180, 1, len(addresses), 0, 0) + request[12:offset + 4])
            for address in addresses:
                packed = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, address)
                response.extend(b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, ttl, len(packed)) + packed)
            try:
                self.socket.sendto(response, peer)
            except OSError:
                pass
        while not self.stop.is_set():
            try:
                request, peer = self.socket.recvfrom(4096)
                threading.Thread(target=respond, args=(request, peer), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def __exit__(self, *args):
        self.stop.set()
        self.socket.close()
        self.worker.join(2)


class Engine(AbstractContextManager):
    def __init__(self, path, dns, start=True):
        self.process = subprocess.Popen([str(path), '--isolated'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding='utf-8',
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        self.responses = queue.Queue()
        threading.Thread(target=lambda: [self.responses.put(json.loads(line)) for line in self.process.stdout], daemon=True).start()
        self.sequence = 0
        self.config = self.ask('default_config')
        self.port = free_port()
        dns_port = free_port()
        while dns_port == self.port:
            dns_port = free_port()
        self.config.update(listen=f'127.0.0.1:{self.port}', dnsListen=f'127.0.0.1:{dns_port}', dnsServers=[dns.address], dnsTls=[],
                           nodes=[], groups=[], rules=[], finalPolicy='DIRECT', tun=False, connectTimeoutMs=4000)
        self.config['privacy']['blockDirect'] = False
        self.config['probeIntervalSecs'] = 3600
        if start:
            self.ask('start', config=self.config)

    def ask(self, command, **fields):
        self.sequence += 1
        self.process.stdin.write(json.dumps(dict(id=self.sequence, command=command, **fields)) + '\n')
        self.process.stdin.flush()
        response = self.responses.get(timeout=12)
        require(response['id'] == self.sequence, 'Fixture IPC response order changed')
        require(response['ok'], f'Fixture IPC failed: {response.get("error", "unknown")}')
        return response['result']

    def settled(self):
        for _ in range(100):
            state = self.ask('snapshot')
            dialing = state.get('dialing', {})
            if dialing.get('active', 0) == 0 and dialing.get('activeAttempts', 0) == 0 and state.get('dns', {}).get('inFlight', 0) == 0:
                return state
            time.sleep(.01)
        raise AssertionError('Connection scheduling retained caller-owned work')

    def __exit__(self, *args):
        try:
            if self.process.poll() is None:
                self.ask('shutdown')
                self.process.wait(5)
        finally:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(5)
            for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
                pipe.close()


def connect(engine, host, port, barrier=None):
    with socket.socket() as stream:
        stream.settimeout(6)
        stream.connect(('127.0.0.1', engine.port))
        stream.sendall(b'\x05\x01\x00')
        require(exact(stream, 2) == b'\x05\x00', 'Fixture SOCKS negotiation failed')
        if barrier:
            barrier.wait(5)
        started = time.perf_counter()
        encoded = host.encode('ascii')
        stream.sendall(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded + struct.pack('!H', port))
        header = exact(stream, 4)
        if header[1] != 0:
            raise ConnectionError('Fixture destination was unavailable')
        length = 4 if header[3] == 1 else 16 if header[3] == 4 else exact(stream, 1)[0]
        exact(stream, length + 2)
        payload = b'harbor-connection-quality-fixture'
        stream.sendall(payload)
        require(exact(stream, len(payload)) == payload, 'Fixture echo data changed')
        elapsed = (time.perf_counter() - started) * 1000
        stream.shutdown(socket.SHUT_WR)
        while stream.recv(8192):
            pass
        return elapsed


def summary(samples, failures, dns, state):
    ordered = sorted(samples)
    return dict(successfulRequests=len(samples), failedRequests=failures,
                p50Ms=round(statistics.median(ordered), 2) if ordered else None,
                p95Ms=round(ordered[max(0, math.ceil(len(ordered) * .95) - 1)], 2) if ordered else None,
                dnsQueries=dns.count, dnsCounters={key: state.get('dns', {}).get(key) for key in ['hits', 'misses', 'errors', 'entries', 'blocked', 'coalesced', 'upstreamQueries', 'inFlight']}, dialing=state.get('dialing'))


def measure(path, current):
    results = {}
    for mode, samples, ipv6 in [('slow-family', 7, False), ('many-addresses', 3, True), ('burst', 32, False)]:
        with Echo(ipv6) as echo, Dns(mode) as dns, Engine(path, dns) as engine:
            times, failures, failure_details = [], 0, []
            if mode == 'burst':
                barrier = threading.Barrier(samples)
                with ThreadPoolExecutor(max_workers=samples) as workers:
                    futures = [workers.submit(connect, engine, 'shared.fixture.invalid', echo.port, barrier) for _ in range(samples)]
                    for future in futures:
                        try:
                            times.append(future.result())
                        except (OSError, ConnectionError) as error:
                            failures += 1
                            failure_details.append(type(error).__name__ + ': ' + str(error))
            else:
                for index in range(samples):
                    try:
                        times.append(connect(engine, f'case{index}.fixture.invalid', echo.port))
                    except (OSError, ConnectionError) as error:
                        failures += 1
                        failure_details.append(type(error).__name__ + ': ' + str(error))
            state = engine.settled()
            results[mode] = summary(times, failures, dns, state)
            print(('CURRENT' if current else 'BASELINE') + ' ' + mode + ' ' + json.dumps({key: results[mode][key] for key in ['successfulRequests', 'failedRequests', 'p50Ms', 'p95Ms', 'dnsQueries']}), flush=True)
            if current and failures:
                (ROOT / '.cache/connection-quality-failure.json').write_text(json.dumps(dict(scenario=mode, failures=failure_details, state=state), indent=2), encoding='utf-8')
            if current:
                require(failures == 0 and len(times) == samples, f'{mode}: current engine could not complete every request')
                if mode == 'slow-family':
                    require(results[mode]['p95Ms'] < 700, 'A slow DNS family still delayed a ready address')
                if mode == 'burst':
                    require(dns.count == 2 and state['dns']['coalesced'] >= 60, 'Duplicate DNS work was not shared across the burst')

    with Echo() as echo, Dns('memory') as dns, Engine(path, dns) as engine:
        connect(engine, 'remembered.fixture.invalid', echo.port)
        first = engine.settled()
        connect(engine, 'remembered.fixture.invalid', echo.port)
        second = engine.settled()
        engine.ask('clear_dns')
        connect(engine, 'remembered.fixture.invalid', echo.port)
        cleared = engine.settled()
        results['path-memory'] = dict(first=first.get('dialing'), second=second.get('dialing'), afterClear=cleared.get('dialing'))
        if current:
            require(first['dialing']['attempts'] == 2, 'Fixture did not exercise the initial address fallback')
            require(second['dialing']['attempts'] - first['dialing']['attempts'] == 1 and second['dialing']['remembered'] == 1, 'A successful current address was not reused')
            require(cleared['dialing']['attempts'] - second['dialing']['attempts'] == 2, 'Clearing DNS did not invalidate path memory')
            engine.config['privacy']['hideMetadata'] = True
            engine.ask('configure', config=engine.config)
            connect(engine, 'remembered.fixture.invalid', echo.port)
            hidden = engine.settled()
            results['path-memory']['afterHide'] = hidden['dialing']
            require(hidden['dialing']['rememberedPaths'] == 0 and hidden['dialing']['remembered'] == 1, 'Hidden metadata continued retaining or reusing per-host memory')
    with Dns('slow-family') as dns, Engine(path, dns, start=False) as engine:
        engine.config['nodes'] = [dict(name='preflight-fixture', kind='socks5', server='preflight.fixture.invalid', port=9)]
        engine.config['finalPolicy'] = 'preflight-fixture'
        started = time.perf_counter()
        result = engine.ask('preflight', config=engine.config)
        elapsed = (time.perf_counter() - started) * 1000
        require(result['ready'], 'Fixture preflight did not complete')
        results['preflight'] = dict(elapsedMs=round(elapsed, 2), stopped=not engine.ask('snapshot')['running'])
        if current:
            require(elapsed < 700 and results['preflight']['stopped'], 'Preflight waited for the slow family or started listeners')
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, default=Path(os.environ.get('HARBOR_TEST_ENGINE', ROOT / 'target/debug/harbor-engine.exe')))
    parser.add_argument('--baseline', type=Path, default=os.environ.get('HARBOR_BASELINE_ENGINE'))
    args = parser.parse_args()
    engine = args.engine.resolve()
    report = dict(checkedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(), engineSha256=hashlib.sha256(engine.read_bytes()).hexdigest(),
                  fixture='Loopback SOCKS5 and echo servers with local DNS delays; no external requests or system network changes',
                  externalRequests=0, slowFamilyDelayMs=1200, burstSize=32, checks=5, current=measure(engine, True))
    if args.baseline:
        baseline = args.baseline.resolve()
        report['baselineEngineSha256'] = hashlib.sha256(baseline.read_bytes()).hexdigest()
        report['baseline'] = measure(baseline, False)
    report['passed'] = True
    output = ROOT / '.cache/connection-quality.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('PASS 5 connection-quality scenarios; evidence: .cache/connection-quality.json', flush=True)
