#!/usr/bin/env python3
"""coaprobe: hand-built RFC 5176 Disconnect-Request or CoA-Request sent to a radsecproxy udp listener
(default 127.0.0.1:3799), for bench testing of reverse CoA routing.
The shared secret is read from the file named by COAPROBE_SECRET_FILE (default ./coaprobe.secret).
CoA attributes:
  coa:Session-Timeout=N        (27, integer)
  coa:Idle-Timeout=N           (28, integer)
  coa:Mikrotik-Rate-Limit=2M/2M   (VSA 14988/8, string; RouterOS rx/tx [burst...])
  coa:Mikrotik-Address-List=NAME  (VSA 14988/19, string)
  coa:Tunnel-Private-Group-ID=VLAN   (81, tag 0, string)   coa:Tunnel-Type=13 (64)  coa:Tunnel-Medium-Type=6 (65)
  coa:Filter-Id=NAME           (11, string)
usage: coaprobe.py [timeout] [User-Name] [Acct-Session-Id] [Framed-IP-Address] [coa:...]... [noon] [op=] [nas=] [cui=] [oni=] [nasip=]
"""
import hashlib, os, socket, struct, sys, time
secret = open(os.environ.get('COAPROBE_SECRET_FILE', 'coaprobe.secret')).read().strip().encode()
target = (os.environ.get('COAPROBE_HOST', '127.0.0.1'), int(os.environ.get('COAPROBE_PORT', '3799')))
args = sys.argv[1:]
noon = 'noon' in args
kv = dict(a.split('=', 1) for a in args if a.startswith(('op=', 'nas=', 'cui=', 'oni=', 'nasip=')))
args = [a for a in args if a != 'noon' and not a.startswith(('op=', 'nas=', 'cui=', 'oni=', 'nasip='))]
timeout = float(args.pop(0)) if args and args[0].replace('.', '', 1).isdigit() else 12.0
user = args.pop(0) if args and not args[0].startswith('coa:') else None
sess = args.pop(0) if args and not args[0].startswith('coa:') else None
fip = args.pop(0) if args and not args[0].startswith('coa:') else None
coa = [a[4:].split('=', 1) for a in args if a.startswith('coa:')]
opname = kv.get('op', os.environ.get('COAPROBE_OPERATOR_NAME', '4EXAMPLE:GB'))
nasid = kv.get('nas', os.environ.get('COAPROBE_NAS_ID', 'nas'))
def attr(t, v): return struct.pack('BB', t, len(v) + 2) + v
def vsa(vendor, t, v): return attr(26, struct.pack('>I', vendor) + struct.pack('BB', t, len(v) + 2) + v)
def tagged(t, tag, v): return attr(t, bytes([tag]) + v)
attrs = b''
if user: attrs += attr(1, user.encode())
if sess: attrs += attr(44, sess.encode())
if fip: attrs += attr(8, socket.inet_aton(fip))
if 'cui' in kv: attrs += attr(89, kv['cui'].encode())
nasip = kv.get('nasip', os.environ.get('COAPROBE_NAS_IP', '192.0.2.1'))
attrs += attr(4, socket.inet_aton(nasip)) + attr(32, nasid.encode()) + attr(55, struct.pack('>I', int(time.time())))
if not noon: attrs += attr(126, opname.encode())
if 'oni' in kv: attrs += attr(241, b'\x08' + kv['oni'].encode())
code = 40 if not coa else 43
for k, v in coa:
    if k == 'Session-Timeout': attrs += attr(27, struct.pack('>I', int(v)))
    elif k == 'Idle-Timeout': attrs += attr(28, struct.pack('>I', int(v)))
    elif k == 'Filter-Id': attrs += attr(11, v.encode())
    elif k == 'Mikrotik-Rate-Limit': attrs += vsa(14988, 8, v.encode())
    elif k == 'Mikrotik-Address-List': attrs += vsa(14988, 19, v.encode())
    elif k == 'Tunnel-Type': attrs += tagged(64, 0, struct.pack('>I', int(v))[1:])
    elif k == 'Tunnel-Medium-Type': attrs += tagged(65, 0, struct.pack('>I', int(v))[1:])
    elif k == 'Tunnel-Private-Group-ID': attrs += tagged(81, 0, v.encode())
    else: sys.exit(f'unknown coa attribute {k}')
ident = os.urandom(1)[0]
length = 20 + len(attrs)
hdr = struct.pack('>BBH', code, ident, length)
auth = hashlib.md5(hdr + b'\x00' * 16 + attrs + secret).digest()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
t0 = time.time()
s.sendto(hdr + auth + attrs, target)
names = {40: 'Disconnect-Request', 43: 'CoA-Request', 41: 'Disconnect-ACK', 42: 'Disconnect-NAK', 44: 'CoA-ACK', 45: 'CoA-NAK', 52: 'Protocol-Error'}
print(f'{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())} sent {names[code]} id {ident} ({length} bytes): user={user} session={sess} framed-ip={fip} coa={coa} operator-name {"none" if noon else opname} nas {nasip}/{nasid}')
try:
    r, _ = s.recvfrom(4096)
except socket.timeout:
    print('no reply within the timeout'); sys.exit(1)
rc, rid, rl = struct.unpack('>BBH', r[:4])
ok = hashlib.md5(r[:4] + auth + r[20:rl] + secret).digest() == r[4:20]
print(f'reply after {1000*(time.time()-t0):.1f} ms: {names.get(rc, rc)} id {rid} ({rl} bytes), response authenticator {"valid" if ok else "INVALID"}')
p = 20
while p + 2 <= rl:
    t, l = r[p], r[p+1]; v = r[p+2:p+l]
    if t == 101: print('  Error-Cause =', struct.unpack('>I', v)[0])
    elif t == 80: print('  Message-Authenticator present')
    else: print(f'  attr {t} len {l-2}')
    p += l
