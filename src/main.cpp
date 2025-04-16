#include "blockchain.h"
#include <thread>
#include <iostream>
#include <csignal>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

void runNode(AhmiyatChain& chain, int port) {
    chain.startNodeListener(port);
}

void mineBlock(AhmiyatChain& chain, std::string minerId) {
    Wallet wallet;
    chain.registerPublicKey(wallet.publicKey, wallet.publicKey);
    std::vector<Transaction> txs = {Transaction(wallet.publicKey, "Babar", 50.0, 0.001, "BALANCE_CHECK=10")};
    MemoryFragment mem("image", "memories/mountain.jpg", "Mountain trip", wallet.publicKey, 3600);
    chain.addBlock(txs, mem, wallet.publicKey, chain.getBalance(wallet.publicKey));
}

void signalHandler(int signum) {
    log("Interrupt signal (" + std::to_string(signum) + ") received. Shutting down...");
    exit(signum);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (argc < 2) {
        log("Usage: ./ahmiyat <port>");
        return 1;
    }
    int port = std::atoi(argv[1]);

    system("mkdir -p memories certs");

    try {
        AhmiyatChain ahmiyat(8);
        ahmiyat.addNode("Node3", "127.0.0.1", 5003);
        ahmiyat.dht.bootstrap("127.0.0.1", 5001);

        Wallet wallet;
        ahmiyat.registerPublicKey(wallet.publicKey, wallet.publicKey);
        ahmiyat.faucet(wallet.publicKey, 100.0);

        std::thread nodeThread(runNode, std::ref(ahmiyat), port);
        std::thread minerThread(mineBlock, std::ref(ahmiyat), "Miner" + std::to_string(port));

        minerThread.join();
        ahmiyat.stressTest(10);

        log("Balance of genesis: " + std::to_string(ahmiyat.getBalance("genesis")));
        log("Balance of wallet: " + std::to_string(ahmiyat.getBalance(wallet.publicKey)));
        log("Advanced node running on port " + std::to_string(port));

        nodeThread.detach();
        while (true) std::this_thread::sleep_for(std::chrono::seconds(1000));
    } catch (const std::exception& e) {
        log("Main error: " + std::string(e.what()));
        return 1;
    }
    return 0;
}
