"""Routing-mode transitions through isolated IPC and real loopback TCP/UDP flows."""
from contextlib import ExitStack
import copy
import queue
import socket
import struct
import threading


def run(ask, config, available_port, check):
    def require(value):
        if not value:
            raise AssertionError('Routing-mode assertion failed')

    def receive(stream, length):
        data = b''
        while len(data) < length:
            part = stream.recv(length - len(data))
            require(bool(part))
            data += part
        return data

    def fixture_config():
        candidate = copy.deepcopy(config)
        candidate.update(listen=f'127.0.0.1:{available_port()}', dnsListen=f'127.0.0.1:{available_port()}',
                         routingMode='rules', finalPolicy='REJECT',
                         rules=[dict(kind='ip_cidr', value='127.0.0.0/8', policy='DIRECT', enabled=True)])
        candidate['privacy'].update(blockDirect=True, blockedDomains=['blocked.fixture.invalid'])
        return candidate

    def tcp_modes():
        stopped = threading.Event()
        errors = queue.Queue()
        workers = []
        with ExitStack() as stack:
            echo = stack.enter_context(socket.socket())
            echo.bind(('127.0.0.1', 0)); echo.listen(4); echo.settimeout(0.1)
            def serve(stream):
                try:
                    with stream:
                        stream.settimeout(0.1)
                        while not stopped.is_set():
                            try: data = stream.recv(1024)
                            except socket.timeout: continue
                            if not data: break
                            stream.sendall(data)
                except Exception as error:
                    if not stopped.is_set(): errors.put(error)
            def accept():
                try:
                    while not stopped.is_set():
                        try: stream, _ = echo.accept()
                        except socket.timeout: continue
                        worker = threading.Thread(target=serve, args=(stream,), daemon=True)
                        workers.append(worker); worker.start()
                except Exception as error:
                    if not stopped.is_set(): errors.put(error)
            accepting = threading.Thread(target=accept, daemon=True); accepting.start()
            candidate = fixture_config()
            def connect(success=True):
                stream = stack.enter_context(socket.create_connection(('127.0.0.1', int(candidate['listen'].split(':')[1])), 3))
                stream.sendall(b'\x05\x01\x00'); require(receive(stream, 2) == b'\x05\x00')
                stream.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo.getsockname()[1]))
                reply = receive(stream, 10); require(reply[0] == 5 and (reply[1] == 0) == success)
                return stream
            def transfer(stream, data):
                stream.sendall(data); require(receive(stream, len(data)) == data)
            try:
                ask('start', config=candidate)
                existing = connect(); transfer(existing, b'rules-before')
                original_generation = ask('snapshot')['generation']
                candidate['routingMode'] = 'global'; ask('configure', config=candidate)
                require(ask('snapshot')['routingMode'] == 'global')
                connect(False); transfer(existing, b'global-preserves-old')
                current_generation = ask('snapshot')['generation']
                unknown = copy.deepcopy(candidate); unknown['routingMode'] = 'unknown'
                ask('configure', expected=False, config=unknown)
                require(ask('snapshot')['generation'] == current_generation)
                candidate['routingMode'] = 'direct'; candidate['rules'][0]['policy'] = 'REJECT'
                ask('configure', config=candidate)
                new = connect(); transfer(new, b'direct-ignores-rule-and-final')
                transfer(existing, b'direct-preserves-old')
                for host in ['blocked.fixture.invalid', '198.51.100.10']:
                    require(ask('explain', host=host, port=443)['outbound'] == 'REJECT')
                snap = ask('snapshot')
                generations = {flow['generation'] for flow in snap['flows'] if flow['state'] == 'active'}
                require(original_generation in generations and snap['generation'] in generations)
                candidate['routingMode'] = 'rules'; ask('configure', config=candidate)
                connect(False); transfer(existing, b'restored-rules-preserve-old')
                require(ask('explain', host='127.0.0.1', port=443)['ruleIndex'] == 1)
            finally:
                ask('stop'); stopped.set(); accepting.join(2)
                for worker in workers: worker.join(2)
                require(not accepting.is_alive() and all(not worker.is_alive() for worker in workers))
            if not errors.empty(): raise errors.get()

    def udp_modes():
        stopped = threading.Event(); errors = queue.Queue()
        with ExitStack() as stack:
            echo = stack.enter_context(socket.socket(type=socket.SOCK_DGRAM))
            echo.bind(('127.0.0.1', 0)); echo.settimeout(0.1)
            def serve():
                try:
                    while not stopped.is_set():
                        try: data, peer = echo.recvfrom(1024)
                        except socket.timeout: continue
                        echo.sendto(data, peer)
                except Exception as error:
                    if not stopped.is_set(): errors.put(error)
            worker = threading.Thread(target=serve, daemon=True); worker.start()
            candidate = fixture_config()
            def associate():
                control = stack.enter_context(socket.create_connection(('127.0.0.1', int(candidate['listen'].split(':')[1])), 3))
                control.sendall(b'\x05\x01\x00'); require(receive(control, 2) == b'\x05\x00')
                control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
                reply = receive(control, 10); require(reply[:4] == b'\x05\x00\x00\x01')
                datagrams = stack.enter_context(socket.socket(type=socket.SOCK_DGRAM))
                datagrams.bind(('127.0.0.1', 0)); datagrams.settimeout(2)
                relay = (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:10])[0])
                return datagrams, relay
            header = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo.getsockname()[1])
            def transfer(association, data):
                stream, relay = association
                stream.sendto(header + data, relay)
                reply, peer = stream.recvfrom(1024); require(peer == relay and reply == header + data)
            try:
                ask('start', config=candidate)
                existing = associate(); transfer(existing, b'udp-rules')
                candidate['routingMode'] = 'global'; ask('configure', config=candidate)
                transfer(existing, b'udp-old-session')
                rejected, relay = associate(); rejected.settimeout(0.5)
                rejected.sendto(header + b'udp-new-rejected', relay)
                try: rejected.recvfrom(1024); raise AssertionError('New UDP flow ignored global reject')
                except socket.timeout: pass
                require(any(flow['protocol'] == 'UDP' and flow['outbound'] == 'REJECT' for flow in ask('snapshot')['flows']))
                candidate['routingMode'] = 'direct'; candidate['rules'][0]['policy'] = 'REJECT'; ask('configure', config=candidate)
                transfer(associate(), b'udp-new-direct'); transfer(existing, b'udp-still-original')
            finally:
                ask('stop'); stopped.set(); worker.join(2); require(not worker.is_alive())
            if not errors.empty(): raise errors.get()

    check('routing modes change new TCP flows, retain old generations, and reject invalid mode changes atomically', tcp_modes)
    check('routing modes change new UDP sessions while established sessions retain their route', udp_modes)
