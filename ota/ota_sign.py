"""Legacy Android whole-file ZIP signature; public AOSP development test key only.
Format follows pinned AOSP SignApk.java and recovery verifier.cpp in vendor/.
This key is PUBLIC. It is compatibility signing, not proof of our authorship.
"""
import base64
import gzip
import hashlib
import io
import json
import re
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CERT = ROOT / 'vendor/testkey.x509.pem'
KEY = ROOT / 'vendor/testkey.pk8'

def command(args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout

def recovery_key(recovery):
    b = Path(recovery).read_bytes()
    if b[:8] != b'ANDROID!': raise ValueError('Not Android boot image')
    k, _, r, _, _, _, _, page = struct.unpack_from('<8I', b, 8)
    start = page + ((k + page - 1) // page) * page
    data = gzip.decompress(b[start:start+r]); pos = 0
    while pos + 110 <= len(data):
        h = data[pos:pos+110]
        if h[:6] != b'070701': raise ValueError('Unexpected cpio')
        fields = [int(h[6+i*8:14+i*8], 16) for i in range(13)]
        size, n = fields[6], fields[11]
        name = data[pos+110:pos+110+n-1].decode(); off = (pos+110+n+3) & ~3
        raw = data[off:off+size]; pos = (off+size+3) & ~3
        if name == 'res/keys': return raw.decode().strip()
        if name == 'TRAILER!!!': break
    raise ValueError('Recovery key missing')

def check_recovery_key(recovery):
    keys = recovery_key(recovery)
    match = re.fullmatch(r'\{64,0x[0-9a-f]+,\{([0-9,]+)\},\{[0-9,]+\}\}', keys)
    if not match: raise ValueError('Expected one v1 SHA1/RSA exponent3 recovery key')
    words = [int(v) for v in match[1].split(',')]
    if len(words) != 64: raise ValueError('Invalid RSA key length')
    modulus = sum(v << (i*32) for i,v in enumerate(words))
    cert_modulus = int(command(['openssl','x509','-in',str(CERT),'-noout','-modulus']).decode().strip().split('=')[1],16)
    text = command(['openssl','x509','-in',str(CERT),'-noout','-text']).decode()
    if modulus != cert_modulus or 'Exponent: 3 (0x3)' not in text: raise ValueError('Recovery signing key mismatch')

def sign(raw):
    if raw[-22:-18] != b'PK\x05\x06' or raw[-2:] != b'\0\0': raise ValueError('Unsigned ZIP must have empty comment')
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp); (p/'content').write_bytes(raw[:-2])
        command(['openssl','pkcs8','-inform','DER','-in',str(KEY),'-nocrypt','-out',str(p/'key.pem')])
        signature = command(['openssl','cms','-sign','-binary','-noattr','-md','sha1','-in',str(p/'content'),'-signer',str(CERT),'-inkey',str(p/'key.pem'),'-outform','DER'])
    message = b'signed by SignApk\0'
    comment_size = len(message)+len(signature)+6
    if comment_size > 65535: raise ValueError('Signature too large')
    result = raw[:-2]+struct.pack('<H',comment_size)+message+signature+struct.pack('<H',len(signature)+6)+b'\xff\xff'+struct.pack('<H',comment_size)
    verify(result)
    return result

def der_children(raw):
    result=[];pos=0
    while pos<len(raw):
        tag=raw[pos];pos+=1;n=raw[pos];pos+=1
        if n&128:
            size=n&127
            if size==0 or size>4:raise ValueError('Invalid DER length')
            n=int.from_bytes(raw[pos:pos+size],'big');pos+=size
        if pos+n>len(raw):raise ValueError('Truncated DER')
        result.append((tag,raw[pos:pos+n]));pos+=n
    return result

def recovery_signature(signature):
    # Same field sequence as AOSP recovery read_pkcs7(): it does NOT accept
    # CMS signedAttributes. Verify the extracted RSA bytes directly as well.
    root=der_children(signature)
    if len(root)!=1 or root[0][0]!=0x30:raise ValueError('PKCS7 root')
    outer=der_children(root[0][1]);app=der_children(outer[1][1]);signed=der_children(app[0][1])
    fields=signed[3:]
    while fields and fields[0][0] in (0xa0,0xa1):fields=fields[1:]
    if len(fields)!=1 or fields[0][0]!=0x31:raise ValueError('SignerInfos')
    signers=der_children(fields[0][1])
    if len(signers)!=1 or signers[0][0]!=0x30:raise ValueError('Signer count')
    signer=der_children(signers[0][1])
    if len(signer)!=5 or signer[4][0]!=0x04:raise ValueError('Recovery-incompatible signed attributes')
    return signer[4][1]

def verify(raw):
    if len(raw)<28 or raw[-4:-2]!=b'\xff\xff': raise ValueError('Invalid signature footer')
    offset,comment = struct.unpack_from('<H',raw,len(raw)-6)[0],struct.unpack_from('<H',raw,len(raw)-2)[0]
    if not 6<offset<=comment or len(raw)<comment+22: raise ValueError('Invalid signature bounds')
    eocd=raw[-comment-22:]
    if eocd[:4]!=b'PK\x05\x06' or b'PK\x05\x06' in eocd[4:] or struct.unpack_from('<H',eocd,20)[0]!=comment: raise ValueError('Invalid EOCD')
    signature=raw[-offset:-6];content=raw[:-comment-2]
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp);(p/'sig').write_bytes(signature);(p/'content').write_bytes(content)
        (p/'rsa').write_bytes(recovery_signature(signature))
        (p/'public.pem').write_bytes(command(['openssl','x509','-in',str(CERT),'-pubkey','-noout']))
        command(['openssl','dgst','-sha1','-verify',str(p/'public.pem'),'-signature',str(p/'rsa'),str(p/'content')])
        # Ignore embedded certs: signer must verify against the pinned AOSP cert.
        command(['openssl','cms','-verify','-binary','-inform','DER','-in',str(p/'sig'),'-content',str(p/'content'),'-certfile',str(CERT),'-nointern','-noverify','-out',str(p/'verified')])
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.testzip() is not None: raise ValueError('ZIP CRC failed')
    return True
