from flask import Flask, request, jsonify
import os, json, hashlib, time, requests, threading, random, ecdsa, base64, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

def load_json(filename):
    if os.path.exists(filename):
        with open(filename) as f:
            return json.load(f)
    return []

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

app = Flask(__name__)

for file in ["mempool.json", "nodes.json"]:
    if not os.path.exists(file):
        with open(file, "w") as f: json.dump([], f)

CONFIG = "config.json"
if not os.path.exists(CONFIG):
    config = {"node_id": f"node_{random.randint(1000,9999)}", "port": 5001}
    with open(CONFIG, "w") as f: json.dump(config, f)
else:
    config = json.load(open(CONFIG))

contract_state = {}
contracts = {}

def load_contract_state():
    global contract_state, contracts
    contract_state, contracts = {}, {}
    if not os.path.exists("blockchain.json"):
        return
    with open("blockchain.json") as f:
        chain = json.load(f)
        for blk in chain:
            for tx in blk.get("data", []):
                if tx.get("type") == "contract_deploy":
                    cname = tx["contract_name"]
                    code = tx["code"]
                    contracts[cname] = code
                    contract_state[cname] = {}
                elif tx.get("type") == "contract_call":
                    cname = tx["contract_name"]
                    code = contracts.get(cname)
                    if not code: continue
                    try:
                        loc = {}
                        exec(code, {}, loc)
                        if "run" in loc:
                            result = loc["run"](tx.get("input"), contract_state.get(cname, {}))
                            if result == "__SELFDESTRUCT__":
                                contracts.pop(cname, None)
                                contract_state.pop(cname, None)
                            else:
                                contract_state[cname] = result
                    except Exception as e:
                        print(f"[!] Contract '{cname}' failed: {e}")

def get_ip():
    return "127.0.0.1"

def hash_block(block):
    block_copy = block.copy()
    block_copy.pop("hash", None)
    return hashlib.sha256(json.dumps(block_copy, sort_keys=True).encode()).hexdigest()

@app.route("/firstblock", methods=["POST"])
def firstblock():
    print("[*] Syncing nodes and searching for longest valid chain...")
    known_nodes = set()
    chains = []

    def discover_nodes(base_url):
        try:
            r = requests.get(f"{base_url}/nodes", timeout=2)
            for node in r.json():
                if node not in known_nodes:
                    known_nodes.add(node)
                    discover_nodes(node)
        except: pass

    try:
        with open("nodes.json") as f:
            base_nodes = json.load(f)
            for node in base_nodes:
                known_nodes.add(node)
                discover_nodes(node)
    except:
        print("[✗] Cannot read nodes.json")
        return
    
    for node in known_nodes:
        try:
            r = requests.get(f"{node}/chain", timeout=3)
            chain = r.json()
            if isinstance(chain, list) and is_chain_valid(chain):
                chains.append(chain)
        except: pass

    if chains:
        best_chain = max(chains, key=len)
        with open("blockchain.json", "w") as f:
            json.dump(best_chain, f, indent=2)
        print(f"[✓] Chain synced from network. Nodes scanned: {len(known_nodes)}")
    else:
        print("[✗] No valid chains found. Starting fresh.")

def is_chain_valid(chain):
    for i in range(1, len(chain)):
        prev, curr = chain[i - 1], chain[i]
        if curr["previous_hash"] != hash_block(prev):
            return False
        if curr["hash"] != hash_block(curr):
            return False
    return True

def generate_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()

def sign_data(private_key_hex, message: str):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
    signature = sk.sign(message.encode())
    return base64.b64encode(signature).decode()

def verify_signature(public_key_hex, message: str, signature_b64: str):
    try:
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)
        signature = base64.b64decode(signature_b64)
        return vk.verify(signature, message.encode())
    except Exception:
        return False

def get_nodes():
    if os.path.exists("nodes.json"):
        with open("nodes.json") as f:
            return json.load(f)
    return []

def try_restore_chain():
    if not os.path.exists("nodes.json"):
        return False

    try:
        nodes = json.load(open("nodes.json"))
        best_chain = []
        for node in nodes:
            try:
                r = requests.get(f"{node}/chain", timeout=3)
                if r.status_code == 200:
                    remote = r.json()
                    if isinstance(remote, list) and is_chain_valid(remote):
                        if len(remote) > len(best_chain):
                            best_chain = remote
            except:
                continue

        if best_chain:
            with open("blockchain.json", "w") as f:
                json.dump(best_chain, f, indent=2)
            print("[✓] Chain restored from longest valid node")
            return True
    except:
        pass
    return False

def check_and_restore_chain():
    try:
        if os.path.exists("blockchain.json"):
            with open("blockchain.json") as f:
                chain = json.load(f)
            if not is_chain_valid(chain):
                print("[✗] Chain tampered. Attempting restore...")
                if try_restore_chain():
                    print("[✓] Chain restored.")
                else:
                    print("[✗] Restore failed. Exiting.")
                    exit()
            else:
                print("[✓] Chain is valid.")
    except Exception as e:
        print(f"[✗] Chain read error: {e}")
        exit()

def get_last_block():
    if os.path.exists("blockchain.json"):
        with open("blockchain.json") as f:
            chain = json.load(f)
            if chain:
                return chain[-1]
    return None

def save_block(block):
    chain = []
    if os.path.exists("blockchain.json"):
        with open("blockchain.json") as f:
            chain = json.load(f)
    if chain and block["index"] <= chain[-1]["index"]:
        return
    chain.append(block)
    with open("blockchain.json", "w") as f:
        json.dump(chain, f, indent=2)

def add_node(url):
    nodes = get_nodes()
    self_url = f"http://{get_ip()}:{config['port']}"
    if url not in nodes and url != self_url:
        nodes.append(url)
        with open("nodes.json", "w") as f:
            json.dump(nodes, f, indent=2)

def broadcast(endpoint, data):
    for node in get_nodes():
        try:
            requests.post(f"{node}/{endpoint}", json=data, timeout=2)
        except:
            pass

def checkdata():
    try:
        with open("blockchain.json") as f:
            chain = json.load(f)
        if not is_chain_valid(chain):
            print("[!] Chain tampered. Replacing...")
            if replace_chain():
                print("[✓] Chain fixed.")
            else:
                print("[✗] Restore failed. Exiting.")
                os._exit(1)
    except:
        pass

def replace_chain():
    longest = []
    for node in get_nodes():
        try:
            r = requests.get(f"{node}/chain", timeout=3)
            remote = r.json()
            if is_chain_valid(remote) and len(remote) > len(longest):
                longest = remote
        except:
            pass
    if longest:
        with open("blockchain.json", "w") as f:
            json.dump(longest, f, indent=2)
        return True
    return False

def monitor_chain():
    while True:
        try:
            with open("blockchain.json") as f:
                chain = json.load(f)
            if not is_chain_valid(chain):
                print("[!] Chain tampered. Replacing...")
                if replace_chain():
                    print("[✓] Chain fixed.")
                else:
                    print("[✗] Restore failed. Exiting.")
                    os._exit(1)
        except:
            pass

@app.route("/nodes", methods=["GET"])
def api_nodes():
    return jsonify(get_nodes())

@app.route("/data", methods=["POST"])
def add_data():
    tx = request.get_json()

    if not tx:
        return jsonify({"error": "Missing payload"}), 400

    try:
        signature = base64.b64decode(tx.pop("signature"))
        pubkey_pem = tx.pop("pubkey").encode()
        pubkey = serialization.load_pem_public_key(pubkey_pem)

        message = json.dumps(tx, sort_keys=True).encode()
        pubkey.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return jsonify({"error": "Invalid digital signature"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    tx["tx_hash"] = hashlib.sha256(message).hexdigest()
    tx["signature"] = base64.b64encode(signature).decode()
    tx["pubkey"] = pubkey_pem.decode()

    mempool = load_json("mempool.json")
    mempool.append(tx)
    save_json("mempool.json", mempool)

    return jsonify({"status": "added", "tx_hash": tx["tx_hash"]})

@app.route("/mempool", methods=["GET"])
def api_mempool():
    return jsonify(json.load(open("mempool.json")))

@app.route("/chain", methods=["GET"])
def api_chain():
    if os.path.exists("blockchain.json"):
        with open("blockchain.json") as f:
            return jsonify(json.load(f))
    return jsonify([])

@app.route("/receive_block", methods=["POST"])
def receive_block():
    block = request.json
    local = get_last_block()

    if local and block["index"] <= local["index"]:
        return jsonify({"status": "old"})

    if block["hash"] != hash_block(block):
        return jsonify({"status": "invalid"}), 400

    save_block(block)

    try:
        with open("mempool.json", "r+") as f:
            mempool = json.load(f)
            mined = {json.dumps(tx, sort_keys=True) for tx in block.get("data", [])}
            mempool = [tx for tx in mempool if json.dumps(tx, sort_keys=True) not in mined]
            f.seek(0)
            json.dump(mempool, f)
            f.truncate()
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

    return jsonify({"status": "OK"})

@app.route("/register", methods=["POST"])
def register():
    url = request.json.get("url")
    if url:
        add_node(url)
        try:
            my_url = f"http://{get_ip()}:{config['port']}"
            requests.post(f"{url}/register", json={"url": my_url}, timeout=2)
            r = requests.get(f"{url}/chain", timeout=3)
            if is_chain_valid(r.json()):
                with open("blockchain.json", "w") as f:
                    json.dump(r.json(), f, indent=2)
            r = requests.get(f"{url}/mempool", timeout=2)
            with open("mempool.json", "r+") as f:
                mempool = json.load(f)
                for tx in r.json():
                    if tx not in mempool:
                        mempool.append(tx)
                f.seek(0)
                json.dump(mempool, f)
                f.truncate()
        except:
            pass
        return jsonify(get_nodes())
    return jsonify({"error": "Missing URL"}), 400

def sendkine(block, sender=None):
    with open("nodes.json") as f:
        nodes = json.load(f)

    this_node = request.host_url.rstrip("/") if request else "self"
    for node in nodes:
        if node == sender: continue
        try:
            requests.post(
                f"{node}/kine",
                json={"block": block, "from": this_node},
                timeout=3
            )
        except: pass

@app.route("/kine", methods=["POST"])
def kine():
    data = request.get_json(force=True)
    block = data.get("block")
    sender = data.get("from")

    if not block or "data" not in block:
        return jsonify({"error": "invalid"}), 400

    block_id = block.get("hash") or hash_block(block)

    if block_id in seen_blocks:
        return jsonify({"status": "already seen"}), 200
    seen_blocks.add(block_id)

    try:
        with open("mempool.json") as f:
            mempool = json.load(f)

        block_tx = {json.dumps(tx, sort_keys=True) for tx in block["data"]}
        mempool = [tx for tx in mempool if json.dumps(tx, sort_keys=True) not in block_tx]

        with open("mempool.json", "w") as f:
            json.dump(mempool, f, indent=2)

        this_node = f"http://{get_ip()}:{config['port']}"
        for node in get_nodes():
            if node != sender and node != this_node:
                try:
                    requests.post(f"{node}/kine", json={"block": block, "from": this_node}, timeout=2)
                except: pass
        return jsonify({"status": "mempool updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/mine', methods=['POST'])
def mine_block():
    global contract_state, contracts
    try:
        with open("mempool.json") as f:
            mempool = json.load(f)
    except:
        mempool = []
    if not mempool:
        return jsonify({"status": "no tx"})

    blockchain = []
    if os.path.exists("blockchain.json"):
        with open("blockchain.json") as f:
            blockchain = json.load(f)

    prev_block = blockchain[-1] if blockchain else {"hash": "0", "index": -1}

    new_block = {
        "index": prev_block["index"] + 1,
        "timestamp": time.time(),
        "data": mempool,
        "previous_hash": prev_block["hash"],
    }
    new_block["hash"] = hash_block(new_block)

    blockchain.append(new_block)
    with open("blockchain.json", "w") as f:
        json.dump(blockchain, f, indent=2)

    with open("mempool.json", "w") as f:
        json.dump([], f)

    load_contract_state()
    sendkine(new_block)

    return jsonify({"status": "mined", "block": new_block})

i = 0
def run_periodic_tasks():
    global i
    i += 1
    try:
        if i % 10 == 0:
            sync_nodes_with_peers()
    except Exception as e:
        print(f"[!] Error in periodic tasks: {e}")    

def auto_sync():
    while True:
        try:
            checkdata()
            sync_nodes_with_peers()
            for node in get_nodes():
                try:
                    r = requests.get(f"{node}/nodes", timeout=2)
                    for n in r.json():
                        add_node(n)
                except:
                    pass
                try:
                    r = requests.get(f"{node}/chain", timeout=3)
                    remote = r.json()
                    local = json.load(open("blockchain.json")) if os.path.exists("blockchain.json") else []
                    if len(remote) > len(local) and is_chain_valid(remote):
                        with open("blockchain.json", "w") as f:
                            json.dump(remote, f, indent=2)
                except:
                    pass
                try:
                    r = requests.get(f"{node}/mempool", timeout=2)
                    with open("mempool.json", "r+") as f:
                        mempool = json.load(f)
                        for tx in r.json():
                            if tx not in mempool:
                                mempool.append(tx)
                        f.seek(0)
                        json.dump(mempool, f)
                        f.truncate()
                except:
                    pass
        except:
            pass
        time.sleep(10)

def auto_register_bootstrap():
    try:
        bootstrap = input("Bootstrap node (e.g. http://127.0.0.1:5001) or blank: ").strip()
        if bootstrap:
            add_node(bootstrap)
            my_url = f"http://{get_ip()}:{config['port']}"
            requests.post(f"{bootstrap}/register", json={"url": my_url})
    except:
        pass

@app.route("/sync_nodes", methods=["POST"])
def sync_nodes():
    new_nodes = request.json.get("nodes", [])
    current = set(get_nodes())
    updated = list(current.union(new_nodes))

    with open("nodes.json", "w") as f:
        json.dump(updated, f)

    return jsonify({"status": "synced", "total": len(updated)})

def sync_nodes_with_peers():
    local_nodes = set(get_nodes())

    for node in list(local_nodes):
        try:
            res = requests.get(f"{node}/get_nodes", timeout=3)
            if res.status_code == 200:
                remote_nodes = set(res.json().get("nodes", []))
                local_nodes |= remote_nodes
        except:
            pass

    with open("nodes.json", "w") as f:
        json.dump(sorted(local_nodes), f)

def periodic_wrapper():
    while True:
        run_periodic_tasks()
        time.sleep(10)

@app.route("/get_nodes")
def get_nodes_route():
    return jsonify({"nodes": get_nodes()})

@app.route("/search")
def search():
    chain = load_json("blockchain.json")

    user = request.args.get("user")
    name = request.args.get("contract_name")
    tx_type = request.args.get("type")
    tx_hash = request.args.get("hash")

    results = []
    for block in chain:
        for tx in block.get("data", []):
            if (
                (not user or tx.get("user") == user)
                and (not name or tx.get("contract_name") == name)
                and (not tx_type or tx.get("type") == tx_type)
                and (not tx_hash or tx.get("tx_hash") == tx_hash)
            ):
                results.append(tx)
    return jsonify({"results": results})

@app.route("/contract/deploy", methods=["POST"])
def deploy_contract():
    tx = request.get_json()
    if "contract_name" not in tx or "code" not in tx:
        return jsonify({"error": "contract_name and code required"}), 400
    tx["type"] = "contract_deploy"
    tx["timestamp"] = time.time()
    tx["user"] = tx.get("user", "anonymous")
    mempool = load_json("mempool.json")
    mempool.append(tx)
    save_json("mempool.json", mempool)
    return jsonify({"status": "added"})

@app.route("/contract/call", methods=["POST"])
def call_contract():
    tx = request.get_json()
    if "contract_name" not in tx or "input" not in tx:
        return jsonify({"error": "contract_name and input required"}), 400
    tx["type"] = "contract_call"
    tx["timestamp"] = time.time()
    tx["user"] = tx.get("user", "anonymous")
    mempool = load_json("mempool.json")
    mempool.append(tx)
    save_json("mempool.json", mempool)
    return jsonify({"status": "added"})

@app.route("/contract/state", methods=["GET"])
def get_contracts():
    return jsonify({"contracts": list(contracts.keys()), "storage": contract_state})

@app.route("/register_node", methods=["POST"])
def register_node():
    incoming = request.json.get("node")
    if not incoming:
        return jsonify({"status": "error", "msg": "No node provided"}), 400

    nodes = get_nodes()

    if incoming not in nodes:
        nodes.append(incoming)
        with open("nodes.json", "w") as f:
            json.dump(nodes, f)

    try:
        requests.post(f"{incoming}/sync_nodes", json={"nodes": nodes})
    except: pass

    return jsonify({"status": "ok", "msg": "Node registered", "nodes": nodes})

seen_blocks = set()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_data = []
        self.contracts = {}
        self.storage = {}
        self.new_block(previous_hash='1')

    def new_block(self, previous_hash=None):
        block = {
            'index': len(self.chain),
            'timestamp': time.time(),
            'data': self.current_data,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        block['hash'] = self.hash(block)
        self.chain.append(block)
        self.current_data = []
        return block
    
    def add_transaction(self, tx):
        self.current_data.append(tx)

    def deploy_contract(self, contract_name, code, user_id='anonymous'):
        self.contracts[contract_name] = code
        self.storage.setdefault(contract_name, {})
        tx = {
            'type': 'contract_deploy',
            'contract_name': contract_name,
            'code': code,
            'timestamp': time.time(),
            'user': 'anonymous',
            'user_id': user_id
        }
        self.add_transaction(tx)
        return tx

    def call_contract(self, contract_name, input_data, user_id='anonymous'):
        code = self.contracts.get(contract_name)
        if not code:
            return {'error': 'contract not found'}

        local_vars = {}
        exec(code, {}, local_vars)
        run_fn = local_vars.get('run')
        if not run_fn:
            return {'error': 'invalid contract'}

        state = self.storage.get(contract_name, {})
        try:
            new_state = run_fn(input_data, state)
            self.storage[contract_name] = new_state
        except Exception as e:
            return {'error': f'contract execution failed: {str(e)}'}

        tx = {
            'type': 'contract_call',
            'contract_name': contract_name,
            'input': input_data,
            'timestamp': time.time(),
            'user': 'anonymous',
            'user_id': user_id
        }
        self.add_transaction(tx)
        return tx

    def search(self, user_id=None, contract_name=None):
        results = []
        for block in self.chain:
            for tx in block['data']:
                if user_id and tx.get('user_id') != user_id:
                    continue
                if contract_name and tx.get('contract_name') != contract_name:
                    continue
                results.append({
                    'type': tx['type'],
                    'contract_name': tx.get('contract_name'),
                    'input': tx.get('input', ''),
                    'code': tx.get('code', ''),
                    'timestamp': tx.get('timestamp', 0),
                    'user_id': tx.get('user_id')
                })
        return results

    def get_contracts_and_storage(self):
        return {
            'contracts': list(self.contracts.keys()),
            'storage': self.storage
        }

    @staticmethod
    def hash(block):
        block_copy = block.copy()
        block_copy.pop('hash', None)
        return hashlib.sha256(json.dumps(block_copy, sort_keys=True).encode()).hexdigest()

if __name__ == "__main__":
    auto_register_bootstrap()
    firstblock()
    try_restore_chain()
    check_and_restore_chain()
    threading.Thread(target=auto_sync, daemon=True).start()
    threading.Thread(target=monitor_chain, daemon=True).start()
    threading.Thread(target=periodic_wrapper, daemon=True).start()
    app.run(port=config["port"])
