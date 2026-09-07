"""Loopback-only interop with the upstream Xray implementation, never shipped with Harbor."""
from pathlib import Path
import base64, concurrent.futures, datetime, hashlib, http.server, ipaddress, json, os, queue, socket, socketserver, struct, subprocess, threading, time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.cache' / 'interop'
OUT.mkdir(parents=True, exist_ok=True)
UUID = '4a4660d1-06d6-4a56-8e77-d6139be8f657'
PASSWORD = 'harbor-loopback-fixture-password'

def port(udp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

def exact(s, n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n-len(data))
        if not chunk: raise EOFError(f'Expected {n}, got {len(data)} bytes')
        data += chunk
    return data

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        try:
            while data := self.request.recv(32768): self.request.sendall(data)
        except (TimeoutError,ConnectionError):pass
class TcpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data,s=self.request
        if data.startswith(b'session:'):
            s.sendto(str(self.client_address[1]).encode()+b'|'+data+b'|first',self.client_address)
            time.sleep(.015)
            s.sendto(str(self.client_address[1]).encode()+b'|'+data+b'|second',self.client_address)
        else:s.sendto(data,self.client_address)
class Http(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'Harbor independent HTTP fixture\n'
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass

def serve(cls, handler):
    server = cls(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

class Engine:
    def __init__(self):
        self.log = (OUT/'engine.stderr').open('w', encoding='utf-8')
        executable = Path(os.environ.get('HARBOR_TEST_ENGINE', ROOT/'target/debug/harbor-engine.exe')).resolve()
        self.p = subprocess.Popen([str(executable),'--isolated'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, encoding='utf-8')
        self.q = queue.Queue(); self.next = 0
        threading.Thread(target=lambda: [self.q.put(json.loads(line)) for line in self.p.stdout],daemon=True).start()
        self.config = self.ask('default_config')
        self.config.update(listen=f'127.0.0.1:{port()}', dnsListen=f'127.0.0.1:{port(True)}', rules=[], connectTimeoutMs=3000, halfCloseTimeoutSecs=1)
        self.proxy_port = int(self.config['listen'].rsplit(':', 1)[1])
    def ask(self, command, **fields):
        self.next += 1
        self.p.stdin.write(json.dumps(dict(id=self.next,command=command,**fields))+'\n'); self.p.stdin.flush()
        response = self.q.get(timeout=30)
        assert response['id'] == self.next, response
        if not response['ok']: raise RuntimeError(response['error'])
        return response['result']
    def start(self): self.ask('start', config=self.config)
    def use(self,node=None):
        self.config['nodes'] = [node] if node else []
        self.config['finalPolicy'] = node['name'] if node else 'DIRECT'
        return self.ask('configure', config=self.config)
    def socks(self,target):
        s=socket.create_connection(('127.0.0.1',self.proxy_port),timeout=8)
        s.sendall(b'\x05\x01\x00'); assert exact(s,2)==b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',target))
        reply=exact(s,10)
        if reply[1]!=0: s.close(); raise RuntimeError(f'SOCKS reply: {reply[1]}')
        return s
    def close(self):
        try: self.ask('shutdown'); self.p.wait(timeout=5)
        finally:
            if self.p.poll() is None: self.p.kill()
            self.log.close()

def certificates():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Harbor fixture CA')])
    now=datetime.datetime.now(datetime.timezone.utc)
    root=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256())
    leafkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])).issuer_name(name).public_key(leafkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).sign(key,hashes.SHA256())
    (OUT/'cert.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (OUT/'key.pem').write_bytes(leafkey.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return root.public_bytes(serialization.Encoding.PEM).decode()

def reference(ca):
    inbounds=[];nodes=[]
    for kind,network,cipher in [('socks5','tcp',''),('http','tcp',''),('https','tcp',''),('trojan','tcp',''),('trojan','ws',''),('vless','tcp',''),('vless','ws',''),('vmess','tcp','aes-128-gcm'),('vmess','tcp','chacha20-poly1305'),('vmess','ws','aes-128-gcm'),('shadowsocks','tcp','aes-128-gcm'),('shadowsocks','tcp','aes-256-gcm'),('shadowsocks','tcp','chacha20-ietf-poly1305'),('shadowsocks','tcp','2022-blake3-aes-128-gcm'),('shadowsocks','tcp','2022-blake3-aes-256-gcm')]:
        tls=kind in ('https','trojan','vless') or network=='ws'
        p=port();name=f'{kind}/{network}/{cipher or "default"}'
        node=dict(name=name,kind=kind,server='127.0.0.1',port=p,password=PASSWORD,username='fixture',tlsServerName='localhost',cipher=cipher or 'chacha20-ietf-poly1305',uuid=UUID,tls=tls,transport=network,wsPath='/harbor',wsHost='localhost',security=cipher if kind=='vmess' else 'auto',caPem=ca)
        if cipher.startswith('2022-'):node['password']=base64.b64encode(bytes(range(16 if '128' in cipher else 32))).decode()
        if kind in ('socks5','http','https'): settings=dict(accounts=[dict(user='fixture',**{'pass':PASSWORD})],auth='password',udp=True)
        elif kind=='trojan': settings=dict(clients=[dict(password=PASSWORD)])
        elif kind=='vless': settings=dict(clients=[dict(id=UUID)],decryption='none')
        elif kind=='vmess': settings=dict(clients=[dict(id=UUID,alterId=0)])
        else: settings=dict(method=cipher,password=node['password'],network='tcp,udp')
        stream=dict(network=network,security='tls' if tls else 'none')
        if tls:stream['tlsSettings']=dict(certificates=[dict(certificateFile=str(OUT/'cert.pem'),keyFile=str(OUT/'key.pem'))])
        if network=='ws':stream['wsSettings']=dict(path='/harbor')
        inbounds.append(dict(tag=name,listen='127.0.0.1',port=p,protocol='socks' if kind=='socks5' else 'http' if kind=='https' else kind,settings=settings,streamSettings=stream))
        nodes.append(node)
    (OUT/'xray.json').write_text(json.dumps(dict(log=dict(loglevel='warning'),inbounds=inbounds,outbounds=[dict(protocol='freedom')]),indent=2),encoding='utf-8')
    log=(OUT/'xray.log').open('w',encoding='utf-8')
    process=subprocess.Popen([str(ROOT/'.cache/reference/xray.exe'),'run','-c',str(OUT/'xray.json')],stdout=log,stderr=log)
    for _ in range(100):
        if process.poll() is not None: raise RuntimeError('Reference failed: '+(OUT/'xray.log').read_text(encoding='utf-8'))
        try:
            with socket.create_connection(('127.0.0.1',nodes[0]['port']),timeout=.1):break
        except OSError:time.sleep(.05)
    return process,log,nodes

def run():
    echo=serve(TcpServer,Echo);udp=serve(socketserver.ThreadingUDPServer,UdpEcho);origin=serve(http.server.ThreadingHTTPServer,Http)
    target=echo.server_address[1];results=[];engine=None;ref=None;ref_log=None
    def check(name,fn):
        start=time.monotonic()
        try: fn();results.append(dict(name=name,passed=True,seconds=round(time.monotonic()-start,3)));print('PASS',name,flush=True)
        except Exception as e: results.append(dict(name=name,passed=False,error=str(e)));print('FAIL',name,str(e),flush=True)
    try:
        ca=certificates();ref,ref_log,nodes=reference(ca);engine=Engine();engine.start()
        def roundtrip(payload=b'own engine, independent server'):
            with engine.socks(target) as s:s.sendall(payload);assert exact(s,len(payload))==payload
        check('direct SOCKS5 TCP',roundtrip)
        def http_flow():
            with socket.create_connection(('127.0.0.1',engine.proxy_port),timeout=8) as s:
                s.sendall(f'GET http://127.0.0.1:{origin.server_address[1]}/ HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n'.encode());body=b''
                while chunk:=s.recv(8192):body+=chunk
                assert b'200 OK' in body and body.endswith(b'Harbor independent HTTP fixture\n'),body
        check('absolute HTTP request and Host normalization',http_flow)
        def connect_pipeline():
            with socket.create_connection(('127.0.0.1',engine.proxy_port),timeout=8) as s:
                payload=b'pipelined CONNECT payload';s.sendall(f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: local\r\n\r\n'.encode()+payload)
                header=b''
                while not header.endswith(b'\r\n\r\n'):header+=exact(s,1)
                assert b'200 OK' in header;assert exact(s,len(payload))==payload
        check('CONNECT preserves pipelined bytes',connect_pipeline)
        for node in nodes:
            engine.use(node);check('reference TCP '+node['name'],roundtrip)
        engine.use()
        def large():
            payload=os.urandom(2*1024*1024)
            with engine.socks(target) as s:
                def upload():s.sendall(payload);s.shutdown(socket.SHUT_WR)
                t=threading.Thread(target=upload);t.start();reply=exact(s,len(payload));t.join();assert hashlib.sha256(reply).digest()==hashlib.sha256(payload).digest();assert s.recv(1)==b''
        check('2 MiB bidirectional backpressure and half-close',large)
        for node in nodes:
            if node.get('transport','tcp')=='ws':continue
            engine.use(node);check('2 MiB reference stream and bounded half-close '+node['name'],large)
        engine.use()
        def sticky():
            with engine.socks(target) as s:
                s.sendall(b'before');assert exact(s,6)==b'before'
                engine.config['finalPolicy']='REJECT';engine.ask('configure',config=engine.config)
                s.sendall(b'after');assert exact(s,5)==b'after'
                try:engine.socks(target);raise AssertionError('Blocked flow connected')
                except RuntimeError:pass
            engine.use()
        check('hot update preserves established streams and rejects new ones',sticky)
        def reject_invalid():
            generation=engine.ask('snapshot')['generation'];invalid=json.loads(json.dumps(engine.config));invalid['finalPolicy']='missing'
            try:engine.ask('configure',config=invalid);raise AssertionError('Invalid profile accepted')
            except RuntimeError:pass
            assert engine.ask('snapshot')['generation']==generation;roundtrip()
        check('invalid config is rejected atomically',reject_invalid)
        def tls_reject():
            node=dict(next(n for n in nodes if n['kind']=='vless'));node['caPem']='';engine.use(node)
            try:engine.socks(target);raise AssertionError('Untrusted TLS certificate accepted')
            except RuntimeError:pass
            engine.use()
        check('untrusted TLS certificate is rejected',tls_reject)
        def parallel():
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:list(pool.map(lambda _:roundtrip(os.urandom(8192)),range(96)))
        check('96 real parallel flows',parallel)
        def udp_flow():
            with socket.create_connection(('127.0.0.1',engine.proxy_port),timeout=8) as control:
                control.sendall(b'\x05\x01\x00');assert exact(control,2)==b'\x05\x00';control.sendall(b'\x05\x03\x00\x01'+b'\0'*6);reply=exact(control,10);address=(socket.inet_ntoa(reply[4:8]),struct.unpack('!H',reply[8:10])[0])
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                    s.settimeout(6);prefix=b'\0\0\0\x01\x7f\0\0\x01'+struct.pack('!H',udp.server_address[1]);source_ports=set()
                    for i in range(4):
                        data=b'session:'+str(i).encode();s.sendto(prefix+data,address)
                        replies=[]
                        for _ in range(2):
                            response,_=s.recvfrom(65535);payload=response[10:];parts=payload.split(b'|');source_ports.add(parts[0]);assert parts[1]==data;replies.append(parts[2])
                        assert set(replies)=={b'first',b'second'}
                    assert len(source_ports)==1,'UDP source port changed across the association'

        check('direct SOCKS5 UDP',udp_flow)
        for node in nodes:
            if node['kind'] in ('http','https'):continue
            engine.use(node);check('reference UDP '+node['name'],udp_flow)
        engine.use();summary=engine.ask('snapshot');assert summary['accepted']>100;assert summary['downloaded']>=2*1024*1024
    finally:
        if engine:engine.close()
        if ref:ref.terminate();ref.wait(timeout=5)
        if ref_log:ref_log.close()
        for server in (echo,udp,origin):server.shutdown();server.server_close()
        binary=Path(os.environ.get('HARBOR_TEST_ENGINE', ROOT/'target/debug/harbor-engine.exe'))
        (OUT/'results.json').write_text(json.dumps(dict(checkedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),engineSha256=hashlib.sha256(binary.read_bytes()).hexdigest(),reference='Xray v26.3.27; loopback fixtures only',results=results,passed=sum(r['passed'] for r in results),total=len(results)),indent=2),encoding='utf-8')
    assert all(r['passed'] for r in results),'Some interop checks failed'

if __name__=='__main__':run()
