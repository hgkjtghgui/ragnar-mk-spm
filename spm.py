import json
import asyncio
import aiohttp
import aiofiles
import socket
import ssl
import gzip
import time
from io import BytesIO
from datetime import datetime
import jwt as pyjwt
import urllib3
import binascii
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
from protobuf_decoder.protobuf_decoder import Parser
from flask import Flask, request, jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def ua():
    versions = ['4.0.18P6', '4.0.19P7', '4.0.20P1', '4.1.0P3', '4.1.5P2', '4.2.1P8',
                '4.2.3P1', '5.0.1B2', '5.0.2P4', '5.1.0P1', '5.2.0B1', '5.2.5P3',
                '5.3.0B1', '5.3.2P2', '5.4.0P1', '5.4.3B2', '5.5.0P1', '5.5.2P3']
    models = ['SM-A125F', 'SM-A225F', 'SM-A325M', 'SM-A515F', 'SM-A725F', 'SM-M215F', 'SM-M325FV',
              'Redmi 9A', 'Redmi 9C', 'POCO M3', 'POCO M4 Pro', 'RMX2185', 'RMX3085',
              'moto g(9) play', 'CPH2239', 'V2027', 'OnePlus Nord', 'ASUS_Z01QD']
    android_versions = ['9', '10', '11', '12', '13', '14']
    languages = ['en-US', 'es-MX', 'pt-BR', 'id-ID', 'ru-RU', 'hi-IN']
    countries = ['USA', 'MEX', 'BRA', 'IDN', 'RUS', 'IND']
    return f"GarenaMSDK/{random.choice(versions)}({random.choice(models)};Android {random.choice(android_versions)};{random.choice(languages)};{random.choice(countries)};)"

def encAEs(hexStr):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(bytes.fromhex(hexStr), AES.block_size)).hex()

def decAEs(hexStr):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(bytes.fromhex(hexStr)), AES.block_size).hex()

def encPacket(hexStr, k, iv):
    return AES.new(k, AES.MODE_CBC, iv).encrypt(pad(bytes.fromhex(hexStr), 16)).hex()

def decPacket(hexStr, k, iv):
    return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(bytes.fromhex(hexStr)), 16).hex()

def encVarint(n):
    if n < 0: return b''
    h = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n: b |= 0x80
        h.append(b)
        if not n: break
    return bytes(h)

def createVarint(field, value):
    return encVarint((field << 3) | 0) + encVarint(value)

def createLength(field, value):
    hdr = encVarint((field << 3) | 2)
    enc = value.encode() if isinstance(value, str) else value
    return hdr + encVarint(len(enc)) + enc

def createProto(fields):
    pkt = bytearray()
    for f, v in fields.items():
        if isinstance(v, dict):
            nested = createProto(v)
            pkt.extend(createLength(f, nested))
        elif isinstance(v, int):
            pkt.extend(createVarint(f, v))
        elif isinstance(v, (str, bytes)):
            pkt.extend(createLength(f, v))
    return pkt

def decodeHex(h):
    r = hex(h)[2:]
    return "0" + r if len(r) == 1 else r

def fixParsed(parsed):
    d = {}
    for r in parsed:
        fd = {'wire_type': r.wire_type}
        if r.wire_type in ("varint", "string", "bytes"):
            fd['data'] = r.data
        elif r.wire_type == 'length_delimited':
            fd['data'] = fixParsed(r.data.results)
        d[r.field] = fd
    return d

def decodePacket(hexInput):
    try:
        parsed = Parser().parse(hexInput)
        return json.dumps(fixParsed(parsed))
    except Exception:
        return None

def xBunner():
    av = ['902000016', '902000031', '902000011', '902000065',
          '902000204', '902000192', '902000191', '902000179',
          '902000133', '902045001', '902038023', '902048004',
          '902039014', '902000063', '902000306', '902047009']
    return int(random.choice(av))

def genPkt(pkt, n, k, iv):
    enc = encPacket(pkt, k, iv)
    l = decodeHex(len(enc) // 2)
    if len(l) == 2: hdr = n + "000000"
    elif len(l) == 3: hdr = n + "00000"
    elif len(l) == 4: hdr = n + "0000"
    elif len(l) == 5: hdr = n + "000"
    else: hdr = n + "000000"
    return bytes.fromhex(hdr + l + enc)

def openRoom(k, iv):
    f = {1: 2, 2: {1: 1, 2: 15, 3: 5, 4: "[FF0000]JAAgwar", 5: "1", 6: 12, 7: 1,
                    8: 1, 9: 1, 11: 1, 12: 2, 14: 36981056,
                    15: {1: "IDC3", 2: 126, 3: "ME"},
                    16: "\u0001\u0003\u0004\u0007\t\n\u000b\u0012\u000f\u000e\u0016\u0019\u001a \u001d",
                    18: 2368584, 27: 1, 34: "\u0000\u0001", 40: "en", 48: 1,
                    49: {1: 21}, 50: {1: 36981056, 2: 2368584, 5: 2}}}
    return genPkt(str(createProto(f).hex()), '0E15', k, iv)

def spmRoom(k, iv, uid):
    f = {1: 22, 2: {1: int(uid)}}
    return genPkt(str(createProto(f).hex()), '0E15', k, iv)

async def gAccess(u, p, session):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": ua(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(u),
        "password": str(p),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    async with session.post(url, headers=headers, data=data, ssl=False) as resp:
        if resp.status == 200:
            js = await resp.json()
            return js.get('access_token'), js.get('open_id')
    return None, None

async def majorLogin(pyl, session):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = aiohttp.TCPConnector(ssl=ctx)
    async with aiohttp.ClientSession(connector=conn) as sess:
        headers = {
            'X-Unity-Version': '2022.3.47f1',
            'ReleaseVersion': 'OB53',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'loginbp.ggpolarbear.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'deflate, gzip'
        }
        async with sess.post("https://loginbp.ggpolarbear.com/MajorLogin", headers=headers, data=pyl) as resp:
            raw = await resp.read()
            if resp.headers.get('Content-Encoding') == 'gzip':
                raw = gzip.decompress(raw)
            if resp.status in (200, 201):
                return raw
    return None

async def getPorts(tok, pyl, session):
    headers = {
        'Expect': '100-continue',
        'Authorization': f'Bearer {tok}',
        'X-Unity-Version': '2022.3.47f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB53',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
        'Host': 'clientbp.ggpolarbear.com',
        'Connection': 'close',
        'Accept-Encoding': 'deflate, gzip'
    }
    async with session.post("https://clientbp.ggpolarbear.com/GetLoginData", headers=headers, data=pyl, ssl=False) as resp:
        raw = await resp.read()
        d = json.loads(decodePacket(raw.hex()))
        a1, a2 = d['32']['data'], d['14']['data']
        return a1[:len(a1)-6], a1[len(a1)-5:], a2[:len(a2)-6], a2[len(a2)-5:]

def getKiv(raw):
    class _runtime_version:
        class Domain: PUBLIC = 0
        @staticmethod
        def ValidateProtobufRuntimeVersion(*args, **kwargs): return True
    _runtime_version.ValidateProtobufRuntimeVersion()
    _sym_db = _symbol_database.Default()
    DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10my_message.proto\">\n\tMyMessage\x12\x0f\n\x07\x66ield21\x18\x15 \x01(\x03\x12\x0f\n\x07\x66ield22\x18\x16 \x01(\x0c\x12\x0f\n\x07\x66ield23\x18\x17 \x01(\x0c\x62\x06proto3')
    _globals = globals()
    _builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
    _builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'my_message_pb2', _globals)
    MyMessage = _globals['MyMessage']
    m = MyMessage()
    m.ParseFromString(raw)
    ts = Timestamp()
    ts.FromNanoseconds(m.field21)
    return ts.seconds * 1_000_000_000 + ts.nanos, m.field22, m.field23

def buildAuth(jwtTok, k, iv, ts):
    dec = pyjwt.decode(jwtTok, options={"verify_signature": False})
    enc = hex(dec['account_id'])[2:]
    tsH = decodeHex(ts)
    jH = jwtTok.encode().hex()
    hLen = hex(len(encPacket(jH, k, iv)) // 2)[2:]
    padMap = {9: '0000000', 8: '00000000', 10: '000000', 7: '000000000'}
    pad = padMap.get(len(enc), '00000000')
    return f'0115{pad}{enc}{tsH}00000{hLen}' + encPacket(jH, k, iv)

async def login(u, p, session):
    at, oid = await gAccess(u, p, session)
    if not at: return None
    dT = bytes.fromhex('1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132302e31'
                       '4232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e323032323035'
                       '31382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960'
                       '800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e3220415658'
                       '2041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f'
                       '70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d'
                       '396631362d303866653964336336353333a2010e3137362e32382e3133392e313835aa01026172b2012'
                       '03433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616'
                       'e6468656c64ca010d4f6e65506c7573204135303130ea014063363961653230386661643732373338623'
                       '637346232383437623530613361316466613235643161313966616537343566633736616334613065343'
                       '134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636'
                       '630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003af13f80384078004'
                       'a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e64'
                       '74732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c6962'
                       '2f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317'
                       'c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b4'
                       '3376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139'
                       '303236a80503b205094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f2'
                       '05704b717348543857393347646347335a6f7a454e6646775648746d377171316552554e6149444e6752'
                       '6f626f7a4942744c4f695943633459367a767670634943787a514632734f453463627974774c7334785a'
                       '62526e70524d706d5752514b6d654f35766373386e51594268777148374bf805e7e406880601900601'
                       '9a060134a2060134b2062213521146500e590349510e460900115843395f005b510f685b560a61075'
                       '76d0f0366')
    dT = dT.replace(b'2025-11-26 01:51:28', str(datetime.now())[:-7].encode())
    dT = dT.replace(b'c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94', at.encode())
    dT = dT.replace(b'4306245793de86da425a52caadf21eed', oid.encode())
    dT = dT.replace(b'1.120.1', b'1.123.8')
    pyl = bytes.fromhex(encAEs(dT.hex()))
    raw = await majorLogin(pyl, session)
    if not raw: return None
    d = json.loads(decodePacket(raw.hex()))
    jwtTok = d['8']['data']
    ts, k, iv = getKiv(raw)
    ip, port, ip2, port2 = await getPorts(jwtTok, pyl, session)
    auth = buildAuth(jwtTok, k, iv, ts)
    return auth, k, iv, ip, port, ip2, port2

class AsyncCli:
    def __init__(self, u, p):
        self.u = u
        self.p = p
        self.key = None
        self.iv = None
        self.reader1 = self.writer1 = None
        self.reader2 = self.writer2 = None
        self.alive = False
        self.task = asyncio.create_task(self._run())

    async def _run(self):
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    res = await login(self.u, self.p, session)
                    if not res:
                        await asyncio.sleep(10)
                        continue
                    auth, k, iv, ip, port, ip2, port2 = res
                    self.key, self.iv = k, iv

                    self.reader1, self.writer1 = await asyncio.open_connection(ip, int(port))
                    self.writer1.write(bytes.fromhex(auth))
                    await self.writer1.drain()
                    await asyncio.sleep(0.3)
                    await self.reader1.read(1024)

                    self.reader2, self.writer2 = await asyncio.open_connection(ip2, int(port2))
                    self.writer2.write(bytes.fromhex(auth))
                    await self.writer2.drain()
                    await asyncio.sleep(0.2)

                    self.alive = True
                    async with _clis_lock:
                        _clis.append(self)
                    print(f'[+] {self.u} connected')

                    while True:
                        try:
                            data = await asyncio.wait_for(self.reader1.read(4096), timeout=30)
                            if not data:
                                break
                        except asyncio.TimeoutError:
                            continue
            except Exception as e:
                print(f'[-] {self.u}: {e}')
            finally:
                self.alive = False
                async with _clis_lock:
                    if self in _clis:
                        _clis.remove(self)
                for w in (self.writer1, self.writer2):
                    if w:
                        w.close()
                        await w.wait_closed()
                self.reader1 = self.writer1 = self.reader2 = self.writer2 = None
            await asyncio.sleep(5)

_clis = []
_clis_lock = asyncio.Lock()
_tasks = {}
_MAX_ACTIVE = 50
_active_semaphore = asyncio.Semaphore(_MAX_ACTIVE)
_loop = None

async def _spamLoop(uid, stop_event):
    while not stop_event.is_set():
        async with _clis_lock:
            snap = [(c.writer2, c.key, c.iv, c.u) for c in _clis if c.alive and c.writer2 and c.key]
        for writer2, k, iv, u in snap:
            if stop_event.is_set():
                break
            try:
                roomPkt = openRoom(k, iv)
                spmPkt = spmRoom(k, iv, uid)
                writer2.write(roomPkt)
                await writer2.drain()
                for _ in range(10):
                    if stop_event.is_set():
                        break
                    writer2.write(spmPkt)
                    await writer2.drain()
                    await asyncio.sleep(0.05)
            except Exception as e:
                print(f'spam err {u}: {e}')
        await asyncio.sleep(0.3)

def add(uid):
    if uid in _tasks:
        return False
    stop = asyncio.Event()
    task = asyncio.create_task(_spamLoop(uid, stop))
    _tasks[uid] = (task, stop)
    return True

def remove(uid):
    if uid not in _tasks:
        return False
    task, stop = _tasks.pop(uid)
    stop.set()
    task.cancel()
    return True

def active():
    return list(_tasks.keys())

async def init():
    async with aiofiles.open("accs.json", "r") as f:
        content = await f.read()
        accs = json.loads(content)
    items = list(accs.items())
    bSz = 5
    for i in range(0, len(items), bSz):
        batch = items[i:i+bSz]
        for u, p in batch:
            AsyncCli(u, p)
        print(f'[boot] batch {i//bSz+1}/{(len(items)+bSz-1)//bSz} — {len(batch)} accs')
        await asyncio.sleep(2)

async def _wAdd(uid):
    return add(uid)

async def _wRemove(uid):
    return remove(uid)

@app.route('/spam', methods=['GET'])
def start_spam():
    uid = request.args.get('user_id')
    if not uid or not uid.isdigit():
        return jsonify({'status': 'error', 'message': 'Missing or invalid user_id parameter'}), 400
    
    # التحقق إذا كان السبام يعمل بالفعل
    if uid in _tasks:
        return jsonify({'status': 'error', 'message': f' السبام يعمل بالفعل على المستخدم: {uid}'})
    
    ok = asyncio.run_coroutine_threadsafe(_wAdd(uid), _loop).result(timeout=5)
    if ok:
        return jsonify({'status': 'success', 'message': f' تم بدء السبام على المستخدم: {uid}'})
    else:
        return jsonify({'status': 'error', 'message': f' السبام يعمل بالفعل على المستخدم: {uid}'})

@app.route('/stop', methods=['GET'])
def stop_spam():
    uid = request.args.get('user_id')
    if not uid or not uid.isdigit():
        return jsonify({'status': 'error', 'message': 'Missing or invalid user_id parameter'}), 400
    
    # التحقق إذا كان السبام يعمل
    if uid not in _tasks:
        return jsonify({'status': 'error', 'message': f' لا يوجد سبام نشط على المستخدم: {uid}'})
    
    ok = asyncio.run_coroutine_threadsafe(_wRemove(uid), _loop).result(timeout=5)
    if ok:
        return jsonify({'status': 'success', 'message': f' تم إيقاف السبام على المستخدم: {uid}'})
    else:
        return jsonify({'status': 'error', 'message': f' لا يوجد سبام نشط على المستخدم: {uid}'})

@app.route('/status', methods=['GET'])
def get_status():
    active_targets = list(_tasks.keys())
    return jsonify({
        'status': 'success',
        'active_spams': active_targets,
        'active_clients': len(_clis),
        'total_active_spams': len(active_targets)
    })

_loop = None

if __name__ == '__main__':
    from threading import Thread
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    
    def runFlask():
        try:
            app.run(host='0.0.0.0', port=5000, threaded=True, use_reloader=False, debug=False)
        except Exception as e:
            print(f'[flask err] {e}')
    
    Thread(target=_loop.run_forever, daemon=True).start()
    asyncio.run_coroutine_threadsafe(init(), _loop)
    print('[*] API running on http://0.0.0.0:5000')
    print('[*] Endpoints:')
    print('    GET /spam?user_id=UID - Start spam')
    print('    GET /stop?user_id=UID - Stop spam')
    print('    GET /status - Check status')
    runFlask()
