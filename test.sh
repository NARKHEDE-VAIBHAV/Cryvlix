#!/bin/bash
set -e

echo -e "\n[1] Deploying contracts..."
curl -s -X POST http://localhost:5001/data \
  -H "Content-Type: application/json" \
  -d '{
    "type": "contract_deploy",
    "contract_name": "counter",
    "code": "def run(input, state):\n if input == \"inc\":\n  state[\"count\"] = state.get(\"count\", 0) + 1\n return state",
    "user": "alice",
    "tx_hash": "hash_counter_deploy"
  }'

curl -s -X POST http://localhost:5002/data \
  -H "Content-Type: application/json" \
  -d '{
    "type": "contract_deploy",
    "contract_name": "math",
    "code": "def run(input, state):\n if input == \"double\":\n  state[\"value\"] = state.get(\"value\", 1) * 2\n return state",
    "user": "bob",
    "tx_hash": "hash_math_deploy"
  }'

echo -e "\n[2] Calling contracts..."
curl -s -X POST http://localhost:5003/data \
  -H "Content-Type: application/json" \
  -d '{
    "type": "contract_call",
    "contract_name": "counter",
    "input": "inc",
    "user": "alice",
    "tx_hash": "hash_counter_call"
  }'

curl -s -X POST http://localhost:5004/data \
  -H "Content-Type: application/json" \
  -d '{
    "type": "contract_call",
    "contract_name": "math",
    "input": "double",
    "user": "bob",
    "tx_hash": "hash_math_call"
  }'

echo -e "\n[3] Adding custom data..."
curl -s -X POST http://localhost:5001/data \
  -H "Content-Type: application/json" \
  -d '{
    "type": "data",
    "data": "test123",
    "password":"12345678",
    "tx_hash": "hash_custom_data"
  }'

echo -e "\n[4] Mining block..."
curl -s -X POST http://localhost:5002/mine

echo -e "\n[5] Search by user (alice)..."
curl -s "http://localhost:5003/search?user=alice" | jq .

echo -e "\n[6] Search by contract_name (math)..."
curl -s "http://localhost:5004/search?contract_name=math" | jq .

echo -e "\n[7] Search by type (contract_call)..."
curl -s "http://localhost:5001/search?type=contract_call" | jq .

echo -e "\n[8] Search by tx_hash (hash_custom_data)..."
curl -s "http://localhost:5002/search?hash=hash_custom_data" | jq .
