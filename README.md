
# 🧱 Cryvlix Blockchain

Cryvlix is a minimalistic yet extendable blockchain framework designed to store any kind of signed data, including smart contracts. It uses ECDSA for signing, supports custom payloads, and allows basic smart contract logic.

## 🔧 Features

- ✅ ECDSA (secp256r1) key generation
- ✅ Digital signature for each payload
- ✅ Public key sharing with each transaction
- ✅ Accepts arbitrary data (contract, JSON, text, binary)
- ✅ Works as a decentralized append-only log
- ✅ Minimal setup: only one `add_data.py` file needed for users


## 🚀 Getting Started
```markdown
### 1. Run Your Local Node (Server)

python3 app.py

Ensure your blockchain node is running at `<your host>`. It must have a `/data` POST endpoint to accept signed JSON.

### 2. Use the Client Script

Clients only need `add_data.py`:

```bash
python3 add_data.py
````

It will:

* Generate keys if not present
* Prepare your JSON data
* Sign it using your private key
* Add public key + signature
* Send it to the blockchain node

---

## 🧪 Example Payload (Stored on Chain)

```json
{
  "sender": "alice",
  "recipient": "bob",
  "amount": 100,
  "signature": "<ECDSA Signature>",
  "pubkey": "<PEM Encoded Public Key>"
}
```

You can also submit larger or nested JSON:

```json
{
  "contract": {
    "type": "supply_chain",
    "details": {
      "origin": "India",
      "steps": ["harvested", "packed", "shipped"]
    }
  },
  "sender": "warehouse_42",
  "signature": "...",
  "pubkey": "..."
}
```

---

## 📦 Smart Contract Support

Cryvlix supports basic contracts embedded in the payload. Example:

```json
{
  "contract": {
    "type": "loan",
    "amount": 5000,
    "code": "def run(input, state):\n if input == \"double\":\n  state[\"value\"] = state.get(\"value\", 1) * 2\n return state",
    "due_date": "2025-12-31"
  }
}
```

---

## 🛡 Security

* Private keys are stored locally per user.
* Signatures are verified before adding to chain.
* No 3rd party dependencies required for users except Python cryptography.

---

## 🔍 Feature Comparison: Cryvlix vs Ethereum

| Feature                   | Cryvlix                         | Ethereum              |
|---------------------------|----------------------------------|------------------------|
| Consensus Mechanism       | ❌ Optional / Manual             | ✅ Proof-of-Work / PoS |
| Virtual Machine (VM)      | ❌ Not available                 | ✅ EVM (Ethereum VM)   |
| Gas Fees                  | ❌ None                          | ✅ Required for TXN    |
| State Storage             | ❌ Not persistent                | ✅ Full account states |
| P2P Network               | 🟡 Basic sync only (Planned to upgrade )     | ✅ Fully decentralized |
| Smart Contract Execution  | 🟡 Manual/backend execution      | ✅ On-chain runtime    |
| Transaction Validation    | ✅ Hash & Signature based        | ✅ Hash & Signature    |
| Contract Storage          | ✅ JSON-based off-chain storage  | ✅ On-chain bytecode   |
| Performance               | ✅ Lightweight & fast            | ❌ Slower due to gas   |
| Customizability           | ✅ Fully customizable logic      | ❌ Limited by EVM spec |
| Simplicity                | ✅ Minimalistic Python backend   | ❌ Complex architecture|
| Interoperability          | 🟡 With custom integration       | ✅ Widely supported    |
| Cost to Operate           | ✅ Free                          | ❌ ETH required        |
| Security Model            | 🟡 Basic hash chaining           | ✅ Strong consensus    |
| Blockchain Size           | ✅ Small footprint               | ❌ Large & growing     |
| Use-case Suitability      | ✅ Educational / Prototypes      | ✅ Production-grade    |


---

## 📫 Contribution

You can fork and improve the node logic. Planned upgrades:

* P2P auto-sync
* Contract execution sandbox
* Block explorer UI

---

## 🔗 License

MIT — use it freely.


