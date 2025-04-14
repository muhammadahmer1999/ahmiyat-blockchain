# Ahmiyat Blockchain

A high-performance, sharded, PoS blockchain with AHM coin, IPFS integration, and Metamask support.

## Features
- **Dynamic Sharding**: 4-16 shards, auto-adjusted for load.
- **Proof-of-Stake**: Secure mining with staking rewards.
- **IPFS Integration**: Decentralized memory fragments.
- **Metamask RPC**: Wallet compatibility.
- **TLS Networking**: Encrypted node communication.
- **Governance**: On-chain voting for upgrades.
- **Mobile-Friendly**: Runs on Termux with ngrok.
- **Free Deployment**: Fly.io, Replit support.

## Setup (Termux)
```bash
pkg update && pkg install git clang make cmake openssl leveldb curl python python-pip
pip install flask flask-limiter
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-arm64.tgz
tar -xzf ngrok-v3-stable-linux-arm64.tgz
./ngrok authtoken <your-token>
git clone https://github.com/yourusername/ahmiyat-blockchain.git
cd ahmiyat-blockchain
chmod +x setup_certs.sh
./setup_certs.sh
mkdir build && cd build
cmake ..
make# ahmiyat-blockchain
