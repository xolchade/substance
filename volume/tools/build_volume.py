# Шифрует содержимое «Объёма работы» (content.json) тем же ключом и пользователями, что и календарь стратсессии
# Пример: python3 build_volume.py content.json --admin ЛОГИН:ПАРОЛЬ
# Пользователи (включая гостя и ключ правок) берутся из текущего volume/data.enc.json
import argparse, base64, hashlib, json, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, '..'); STRAT = os.path.join(HERE, '..', '..', 'strat')
b64 = lambda b: base64.b64encode(b).decode(); ub = base64.b64decode
ap = argparse.ArgumentParser(); ap.add_argument('src'); ap.add_argument('--admin', required=True); a = ap.parse_args()
login, pwd = a.admin.split(':', 1)
d = json.load(open(os.path.join(STRAT, 'data.enc.json')))
e = next(x for x in d['users'] if x['u'] == hashlib.sha256(('strat:' + login.lower()).encode()).hexdigest())
kek = PBKDF2HMAC(hashes.SHA256(), 32, ub(e['salt']), e.get('it', d['iter'])).derive((login.lower() + ':' + pwd).encode())
dk = AESGCM(kek).decrypt(ub(e['iv']), ub(e['wk']), None)
iv = os.urandom(12); data = json.dumps(json.load(open(a.src)), ensure_ascii=False).encode()
cur = os.path.join(ROOT, 'data.enc.json'); users = json.load(open(cur))['users'] if os.path.exists(cur) else d['users']
json.dump({'iter': d['iter'], 'users': users, 'iv': b64(iv), 'ct': b64(AESGCM(dk).encrypt(iv, data, None))}, open(os.path.join(ROOT, 'data.enc.json'), 'w'))
print('OK volume/data.enc.json')
