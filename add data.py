import json, hashlib, base64, requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

privkey_b64 = ''''''
pubkey_b64 = ''''''

if not privkey_b64.strip():
    private_key = ec.generate_private_key(ec.SECP256R1())
    privkey_b64 = base64.b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    ).decode()
    pubkey_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    with open(__file__, "r+") as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            if line.strip().startswith("privkey_b64 = ''''''"):
                lines[i] = f"privkey_b64 = '''{privkey_b64}'''\n"
            if line.strip().startswith("pubkey_b64 = ''''''"):
                lines[i] = f"pubkey_b64 = '''{pubkey_b64}'''\n"
        f.seek(0)
        f.writelines(lines)
        f.truncate()
else:
    private_key = serialization.load_pem_private_key(
        base64.b64decode(privkey_b64.encode()), password=None, backend=default_backend()
    )

public_key = private_key.public_key()

# == Prepare & Sign Data ==
data = {
    
#Your Data Here

}

msg = json.dumps(data, sort_keys=True).encode()
signature = base64.b64encode(private_key.sign(msg, ec.ECDSA(hashes.SHA256()))).decode()


data["signature"] = signature
data["pubkey"] = base64.b64decode(pubkey_b64).decode()
res = requests.post("<your host>/data", json=data)
print(res.text)
