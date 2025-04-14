from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import time
import requests
import random

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["100 per day", "10 per minute"])

NODES = ["http://127.0.0.1:5001", "http://127.0.0.1:5002"]

@app.route('/balance', methods=['GET'])
@limiter.limit("50/hour")
def balance():
    try:
        address = request.args.get('address', 'genesis')
        shard = request.args.get('shard', '0')
        balance = 0
        return json.dumps({
            "status": "success",
            "address": address,
            "shard": shard,
            "balance": balance,
            "currency": "AHM",
            "timestamp": int(time.time())
        })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": str(e),
            "timestamp": int(time.time())
        }), 500

@app.route('/tx', methods=['POST'])
@limiter.limit("10/minute")
def tx():
    try:
        data = request.get_json()
        sender = data.get('sender')
        receiver = data.get('receiver')
        amount = data.get('amount', 0.0)
        if not sender or not receiver or amount <= 0:
            raise ValueError("Invalid transaction data")
        return json.dumps({
            "status": "success",
            "message": "Transaction queued",
            "tx": data,
            "timestamp": int(time.time())
        })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": str(e),
            "timestamp": int(time.time())
        }), 500

@app.route('/faucet', methods=['POST'])
@limiter.limit("5/hour")
def faucet():
    try:
        data = request.get_json()
        address = data.get('address')
        amount = data.get('amount', 10.0)
        if not address or amount <= 0:
            raise ValueError("Invalid faucet request")
        return json.dumps({
            "status": "success",
            "message": f"{amount} AHM sent to {address}",
            "timestamp": int(time.time())
        })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": str(e),
            "timestamp": int(time.time())
        }), 500

@app.route('/blocks', methods=['GET'])
@limiter.limit("20/hour")
def blocks():
    try:
        shard = request.args.get('shard', '0')
        return json.dumps({
            "status": "success",
            "shard": shard,
            "blocks": [],
            "timestamp": int(time.time())
        })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": str(e),
            "timestamp": int(time.time())
        }), 500

@app.route('/rpc', methods=['POST'])
@limiter.limit("20/minute")
def rpc():
    try:
        data = request.get_json()
        method = data.get('method')
        params = data.get('params', [])
        if not method:
            raise ValueError("Method required")

        if method == 'eth_getBalance':
            address = params[0].lower()
            balance = 0
            return json.dumps({
                "jsonrpc": "2.0",
                "result": hex(int(balance * 1e18)),
                "id": data.get('id')
            })
        elif method == 'eth_sendTransaction':
            tx = params[0]
            sender = tx.get('from').lower()
            receiver = tx.get('to').lower()
            amount = int(tx.get('value'), 16) / 1e18
            return json.dumps({
                "jsonrpc": "2.0",
                "result": "0x" + ''.join(random.choice('0123456789abcdef') for _ in range(64)),
                "id": data.get('id')
            })
        else:
            return json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Method not found"},
                "id": data.get('id')
            }), 400
    except Exception as e:
        return json.dumps({
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": str(e)},
            "id": data.get('id', 1)
        }), 500

@app.route('/ping', methods=['GET'])
def ping():
    return json.dumps({"status": "ok", "timestamp": int(time.time())})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
