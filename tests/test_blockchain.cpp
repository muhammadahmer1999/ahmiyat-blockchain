#include "../src/blockchain.h"
#include <cassert>
#include <iostream>

int main() {
    AhmiyatChain chain(4);
    Wallet wallet;

    assert(chain.getBalance("genesis", "0") == 1000.0);

    chain.registerPublicKey(wallet.publicKey, wallet.publicKey);
    Transaction tx(wallet.publicKey, "test", 10.0);
    tx.signature = chain.signTransaction(tx);
    assert(chain.verifySignature(tx));

    std::vector<Transaction> txs = {tx};
    MemoryFragment mem("text", "memories/test.txt", "Test", wallet.publicKey, 0);
    chain.addBlock(txs, mem, wallet.publicKey, 0.0);

    chain.faucet(wallet.publicKey, 10.0, "0");
    assert(chain.getBalance(wallet.publicKey, "0") == 10.0);

    std::string status = chain.getShardStatus("0");
    assert(status.find("Blocks: 1") != std::string::npos);

    Transaction crossTx(wallet.publicKey, "test2", 5.0, 0.001, "", "1");
    chain.handleCrossShardTx(crossTx);

    chain.proposeUpgrade(wallet.publicKey, "Upgrade v2");
    chain.voteForUpgrade(wallet.publicKey, wallet.publicKey + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));

    auto blocks = chain.getBlocks("0");
    assert(blocks.has_value() && blocks->size() == 1);

    log("All tests passed");
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
