#!/usr/bin/env python3
"""IAS102 classroom RSA key-code helper. Six-digit codes are identifiers, not cryptographic keys."""
import argparse, getpass, json, secrets, subprocess, sys
from pathlib import Path

ROOT = Path.home() / 'ias102-challenge'
STATE = ROOT / '.key_codes.json'

def openssl(*args, input_bytes=None):
    p = subprocess.run(['openssl', *map(str,args)], input=input_bytes, capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.decode(errors='replace').strip() or 'OpenSSL failed')
    return p.stdout

def load():
    if not STATE.exists():
        sys.exit('No keys found. Run: python3 ~/crypto.py generate-keys')
    return json.loads(STATE.read_text())

def prompt_code(kind, data):
    entered = input(f'Enter {kind} Key Code: ').strip()
    if not secrets.compare_digest(entered, data[kind]):
        sys.exit(f'Invalid {kind.lower()} key code. Operation failed.')
    print(f'{kind} key code accepted. Using the actual RSA key file.')

def generate():
    ROOT.mkdir(exist_ok=True)
    openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',ROOT/'private.pem')
    openssl('pkey','-in',ROOT/'private.pem','-pubout','-out',ROOT/'public.pem')
    codes = secrets.SystemRandom().sample(range(100000,1000000),2)
    STATE.write_text(json.dumps({'Public':str(codes[0]),'Private':str(codes[1])}))
    STATE.chmod(0o600)
    print('REAL RSA KEY PAIR GENERATED (2048-bit)')
    print('Public Key Code :',codes[0]);print('Private Key Code:',codes[1])
    print('Codes are classroom identifiers, NOT actual RSA keys. Keep the private key secret.')

def encrypt():
    data=load();prompt_code('Public',data)
    if not (ROOT/'grades.txt').exists():sys.exit('Missing grades.txt. Complete Challenge 1 first.')
    # RSA OAEP supports short messages. A SHA-256 digest of the report is used for demonstration.
    # Encrypt the digest with RSA public key; actual grade report confidentiality uses AES.
    digest=openssl('dgst','-sha256','-binary',ROOT/'grades.txt')
    openssl('pkeyutl','-encrypt','-pubin','-inkey',ROOT/'public.pem','-pkeyopt','rsa_padding_mode:oaep','-in','/dev/stdin','-out',ROOT/'rsa_message.enc',input_bytes=digest)
    print('RSA encryption successful: encrypted SHA-256 digest saved as rsa_message.enc')

def decrypt():
    data=load();prompt_code('Private',data)
    if not (ROOT/'rsa_message.enc').exists():sys.exit('Missing rsa_message.enc. Run encrypt first.')
    openssl('pkeyutl','-decrypt','-inkey',ROOT/'private.pem','-pkeyopt','rsa_padding_mode:oaep','-in',ROOT/'rsa_message.enc','-out',ROOT/'rsa_message.dec')
    print('RSA decryption successful: recovered digest saved as rsa_message.dec')
    if (ROOT/'grades.txt').exists() and (ROOT/'rsa_message.dec').read_bytes()==openssl('dgst','-sha256','-binary',ROOT/'grades.txt'):
        print('Recovered digest matches the grade report: VERIFIED')
    else: print('Recovered digest does not match the current grade report.')

def sign():
    data=load();prompt_code('Private',data)
    if not (ROOT/'grades.txt').exists():sys.exit('Missing grades.txt')
    openssl('dgst','-sha256','-sign',ROOT/'private.pem','-out',ROOT/'grades.sig',ROOT/'grades.txt')
    print('Digital signature created: grades.sig')

def verify():
    data=load();prompt_code('Public',data)
    if not (ROOT/'grades.sig').exists():sys.exit('Missing grades.sig. Run sign first.')
    p=subprocess.run(['openssl','dgst','-sha256','-verify',str(ROOT/'public.pem'),'-signature',str(ROOT/'grades.sig'),str(ROOT/'grades.txt')],capture_output=True,text=True)
    print((p.stdout+p.stderr).strip())
    if p.returncode:sys.exit('Verification failed: report may have changed.')

def final():
    checks={
        'Original report':(ROOT/'grades.txt').exists(),
        'AES ciphertext':(ROOT/'grades.enc').exists(),
        'Recovered report':(ROOT/'recovered.txt').exists(),
        'RSA public key':(ROOT/'public.pem').exists(),
        'RSA private key':(ROOT/'private.pem').exists(),
        'RSA encrypted digest':(ROOT/'rsa_message.enc').exists(),
        'RSA decrypted digest':(ROOT/'rsa_message.dec').exists(),
        'Digital signature':(ROOT/'grades.sig').exists(),
    }
    if checks['Original report'] and checks['Recovered report']:
        checks['AES recovered content matches']= (ROOT/'grades.txt').read_bytes()==(ROOT/'recovered.txt').read_bytes()
    if checks['Original report'] and checks['RSA decrypted digest']:
        checks['RSA digest matches report']= (ROOT/'rsa_message.dec').read_bytes()==openssl('dgst','-sha256','-binary',ROOT/'grades.txt')
    if checks['Digital signature'] and checks['Original report'] and checks['RSA public key']:
        checks['Signature verification']= subprocess.run(['openssl','dgst','-sha256','-verify',str(ROOT/'public.pem'),'-signature',str(ROOT/'grades.sig'),str(ROOT/'grades.txt')],capture_output=True).returncode==0
    if checks['RSA public key'] and checks['RSA private key']:
        checks['Public/private keys match']=openssl('pkey','-in',ROOT/'private.pem','-pubout')==openssl('pkey','-pubin','-in',ROOT/'public.pem','-pubout')
    for name,ok in checks.items():print(('PASS' if ok else 'FAIL')+' - '+name)
    print('CHALLENGE COMPLETED' if all(checks.values()) else 'CHALLENGE FAILED')

parser=argparse.ArgumentParser(description='IAS102 RSA helper (no menu)')
parser.add_argument('command',choices=['generate-keys','encrypt','decrypt','sign','verify','final-check'])
a=parser.parse_args()
try:
    {'generate-keys':generate,'encrypt':encrypt,'decrypt':decrypt,'sign':sign,'verify':verify,'final-check':final}[a.command]()
except (RuntimeError,FileNotFoundError) as e:sys.exit('ERROR: '+str(e))
