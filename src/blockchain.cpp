
#include "blockchain.h"
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <curl/curl.h>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <sstream>
#include <iomanip>

extern void log(const std::string& message);
extern std::string uploadToIPFS(const std::string& filePath);
extern std::string generateZKProof(const std::string& data);

Transaction::Transaction(std::string s, std::string r, double a, double f, std::string sc, std::string sh) 
    : sender(s), receiver(r), amount(a), fee(f), script(sc), shardId(sh), 
      timestamp(std::chrono::system_clock::now().time_since_epoch().count()) {}

std::string Transaction::toString() const {
    return sender + receiver + std::to_string(amount) + std::to_string(fee) + script + shardId + std::to_string(timestamp);
}

std::string Transaction::getHash() const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)toString().c_str(), toString().length(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool Transaction::executeScript(const std::unordered_map<std::string, double>& balances) const {
    if (script.empty()) return true;
    if (script.find("BALANCE_CHECK") != std::string::npos) {
        try {
            double required = std::stod(script.substr(script.find("=") + 1));
            return balances.count(sender) && balances.at(sender) >= required;
        } catch (const std::exception& e) {
            log("Script execution error: " + std::string(e.what()));
            return false;
        }
    }
    return true;
}

MemoryFragment::MemoryFragment(std::string t, std::string fp, std::string desc, std::string o, int lt) 
    : type(t), filePath(fp), description(desc), owner(o), lockTime(lt) {
    saveToFile();
    ipfsHash = uploadToIPFS(filePath);
}

void MemoryFragment::saveToFile() {
    std::ofstream file(filePath, std::ios::binary);
    if (file.is_open()) {
        file << "Memory Data: " << description;
        file.close();
    } else {
        log("Error saving memory file: " + filePath);
    }
}

std::string AhmiyatBlock::calculateHash() const {
    std::stringstream ss;
    ss << index << timestamp;
    for (const auto& tx : transactions) {
        ss << tx.getHash();
    }
    ss << memory.ipfsHash << previousHash << memoryProof << stakeWeight << shardId;

    std::string input = ss.str();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.length(), hash);

    std::stringstream hashStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hashStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return hashStream.str();
}

bool AhmiyatBlock::isMemoryProofValid(int difficulty) const {
    std::string target(difficulty, '0');
    return hash.substr(0, difficulty) == target;
}

AhmiyatBlock::AhmiyatBlock(int idx, const std::vector<Transaction>& txs, const MemoryFragment& mem, 
                           std::string prevHash, int diff, double stake, std::string sh) 
    : index(idx), transactions(txs), memory(mem), previousHash(prevHash), difficulty(diff), 
      stakeWeight(stake), shardId(sh) {
    timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    mineBlock(stake);
}

void AhmiyatBlock::mineBlock(double minerStake) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    do {
        memoryProof = std::to_string(dis(gen));
        hash = calculateHash();
    } while (!isMemoryProofValid(difficulty) || (minerStake < stakeWeight && stakeWeight > 0));
    log("Block mined in shard " + shardId + " - Hash: " + hash.substr(0, 16));
}

std::string AhmiyatBlock::getHash() const { return hash; }
std::string AhmiyatBlock::getPreviousHash() const { return previousHash; }
double AhmiyatBlock::getStakeWeight() const { return stakeWeight; }
std::string AhmiyatBlock::getShardId() const { return shardId; }
const std::vector<Transaction>& AhmiyatBlock::getTransactions() const { return transactions; }

std::string AhmiyatBlock::serialize() const {
    std::stringstream ss;
    ss << index << "|" << timestamp << "|";
    for (const auto& tx : transactions) {
        ss << tx.sender << "," << tx.receiver << "," << tx.amount << "," << tx.fee << "," 
           << tx.signature << "," << tx.script << "," << tx.shardId << ";";
    }
    ss << "|" << memory.type << "," << memory.ipfsHash << "," << memory.description << ","
       << memory.owner << "," << memory.lockTime << "|" << previousHash << "|" << memoryProof 
       << "|" << stakeWeight << "|" << shardId;
    return ss.str();
}

AhmiyatChain::AhmiyatChain(int shards) : shardCount(shards), keyPair(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free) {
    if (!keyPair) throw std::runtime_error("EC_KEY initialization failed");
    EC_KEY_generate_key(keyPair.get());

    leveldb::Options options;
    options.create_if_missing = true;
    options.write_buffer_size = 16 * 1024 * 1024;
    options.compression = leveldb::kSnappyCompression;
    leveldb::Status status = leveldb::DB::Open(options, "./ahmiyat_db", &db);
    if (!status.ok()) {
        log("Failed to open LevelDB: " + status.ToString());
        throw std::runtime_error("DB initialization failed");
    }

    for (int i = 0; i < shardCount; i++) {
        std::string shardId = std::to_string(i);
        shardDifficulties[shardId] = 4;
        if (shards[shardId].empty()) {
            std::vector<Transaction> genesisTx = {Transaction("system", "genesis", 1000.0, 0.001, "", shardId)};
            genesisTx[0].signature = signTransaction(genesisTx[0]);
            MemoryFragment genesisMemory("text", "memories/genesis_" + shardId + ".txt", 
                                        "Shard " + shardId + " genesis", "system", 0);
            AhmiyatBlock genesisBlock(0, genesisTx, genesisMemory, "0", shardDifficulties[shardId], 0.0, shardId);
            shards[shardId].push_back(genesisBlock);
            saveBlockToDB(genesisBlock);
            shardBalances[shardId]["genesis"] = 1000.0;
            shardStakes[shardId]["genesis"] = 0.0;
            totalMined += 1000.0;
        }
    }

    nodes.emplace_back("Node1", "127.0.0.1", 5001);
    nodes.emplace_back("Node2", "127.0.0.1", 5002);
    for (const auto& node : nodes) dht.addPeer(node);
}

AhmiyatChain::~AhmiyatChain() = default;

void AhmiyatChain::broadcastBlock(const AhmiyatBlock& block, const Node& sender) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log("SSL_CTX creation failed");
        return;
    }

    std::string blockData = block.serialize();
    std::vector<Node> peers = dht.findPeers(sender.nodeId);
    std::vector<std::thread> broadcastThreads;

    for (const auto& node : peers) {
        if (node.nodeId != sender.nodeId) {
            broadcastThreads.emplace_back([&, node, blockData]() {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) {
                    log("Socket creation failed for " + node.nodeId);
                    return;
                }

                sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(node.port);
                if (inet_pton(AF_INET, node.ip.c_str(), &addr.sin_addr) <= 0) {
                    log("Invalid IP for " + node.nodeId);
                    close(sock);
                    return;
                }

                SSL* ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sock);
                if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
                    if (SSL_connect(ssl) == 1) {
                        SSL_write(ssl, blockData.c_str(), blockData.length());
                        log("TLS Broadcast to " + node.nodeId + " in shard " + block.getShardId());
                    } else {
                        log("TLS handshake failed with " + node.nodeId);
                    }
                } else {
                    log("Failed to connect to " + node.nodeId);
                }
                SSL_free(ssl);
                close(sock);
            });
        }
    }
    for (auto& t : broadcastThreads) t.join();
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

std::string AhmiyatChain::signTransaction(const Transaction& tx) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)tx.toString().c_str(), tx.toString().length(), hash);

    unsigned char signature[256];
    unsigned int sigLen = 0;
    if (ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sigLen, keyPair.get()) != 1) {
        log("Signature generation failed for tx: " + tx.getHash());
        return "";
    }

    std::stringstream sigStream;
    for (unsigned int i = 0; i < sigLen; i++) {
        sigStream << std::hex << std::setw(2) << std::setfill('0') << (int)signature[i];
    }
    return sigStream.str();
}

bool AhmiyatChain::verifySignature(const Transaction& tx) const {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (!publicKeys.count(tx.sender)) {
        log("Public key not found for " + tx.sender);
        return false;
    }

    EC_KEY* pubKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!pubKey) {
        log("EC_KEY creation failed");
        return false;
    }

    const char* pubKeyHex = publicKeys.at(tx.sender).c_str();
    BIGNUM* bn = nullptr;
    if (!BN_hex2bn(&bn, pubKeyHex)) {
        EC_KEY_free(pubKey);
        return false;
    }
    EC_POINT* point = EC_POINT_new(EC_GROUP_new_by_curve_name(NID_secp256k1));
    if (!EC_POINT_set_compressed_point_GFp(EC_GROUP_new_by_curve_name(NID_secp256k1), point, bn, 0, nullptr)) {
        BN_free(bn);
        EC_KEY_free(pubKey);
        return false;
    }
    if (!EC_KEY_set_public_key(pubKey, point)) {
        BN_free(bn);
        EC_POINT_free(point);
        EC_KEY_free(pubKey);
        return false;
    }
    EC_POINT_free(point);
    BN_free(bn);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)tx.toString().c_str(), tx.toString().length(), hash);

    std::vector<unsigned char> sig;
    for (size_t i = 0; i < tx.signature.length(); i += 2) {
        std::string byte = tx.signature.substr(i, 2);
        sig.push_back(std::stoi(byte, nullptr, 16));
    }

    int result = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, sig.data(), sig.size(), pubKey);
    EC_KEY_free(pubKey);

    if (result == 1) {
        log("Signature verified for tx: " + tx.getHash());
        return true;
    }
    log("Signature verification failed for tx: " + tx.getHash());
    return false;
}

bool AhmiyatChain::validateTransaction(const Transaction& tx, const std::string& shardId) {
    if (processedTxs.count(tx.signature)) {
        log("Duplicate tx: " + tx.getHash());
        return false;
    }
    if (!verifySignature(tx)) {
        log("Invalid signature for tx: " + tx.getHash());
        return false;
    }
    if (!tx.executeScript(shardBalances[shardId])) {
        log("Script execution failed for tx: " + tx.getHash());
        return false;
    }
    if (shardBalances[shardId][tx.sender] < tx.amount + tx.fee) {
        log("Insufficient balance for " + tx.sender + " in shard " + shardId);
        return false;
    }
    return true;
}

void AhmiyatChain::saveBlockToDB(const AhmiyatBlock& block) {
    leveldb::WriteOptions options;
    options.sync = false;
    leveldb::Status status = db->Put(options, block.getHash(), block.serialize());
    if (!status.ok()) {
        log("Error saving block to DB: " + status.ToString());
    }
}

void AhmiyatChain::loadChainFromDB() {
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        log("Loaded block from DB: " + it->key().ToString());
    }
    delete it;
}

void AhmiyatChain::syncChain(const std::string& blockData) {
    try {
        std::string shardId = blockData.substr(blockData.rfind("|") + 1);
        std::string hash = blockData.substr(blockData.rfind("|", blockData.rfind("|") - 1) + 1, 
                                           blockData.rfind("|") - blockData.rfind("|", blockData.rfind("|") - 1) - 1);
        std::lock_guard<std::mutex> lock(chainMutex);
        if (std::find_if(shards[shardId].begin(), shards[shardId].end(), 
                         [&](const AhmiyatBlock& b) { return b.getHash() == hash; }) == shards[shardId].end()) {
            log("Synced new block in shard " + shardId + ": " + hash);
        }
    } catch (const std::exception& e) {
        log("Sync error: " + std::string(e.what()));
    }
}

void AhmiyatChain::updateReward(std::string shardId) {
    if (shards[shardId].size() % HALVING_INTERVAL == 0 && shards[shardId].size() > 0) {
        blockReward /= 2;
        stakingReward *= 1.05;
        log("Shard " + shardId + ": Block reward halved to: " + std::to_string(blockReward));
    }
}

bool AhmiyatChain::validateBlock(const AhmiyatBlock& block) {
    std::string shardId = block.getShardId();
    std::lock_guard<std::mutex> lock(chainMutex);
    if (shards[shardId].empty() && block.getPreviousHash() != "0") return false;
    if (!shards[shardId].empty() && block.getPreviousHash() != shards[shardId].back().getHash()) return false;
    if (block.getHash() != block.calculateHash()) return false;
    for (const auto& tx : block.getTransactions()) {
        if (!validateTransaction(tx, shardId)) return false;
    }
    return true;
}

void AhmiyatChain::compressState(std::string shardId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    std::stringstream ss;
    for (const auto& [addr, bal] : shardBalances[shardId]) {
        ss << addr << bal;
    }
    std::string proof = generateZKProof(ss.str());
    log("Shard " + shardId + " state compressed with ZKP: " + proof);
}

std::string AhmiyatChain::assignShard(const Transaction& tx) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)tx.sender.c_str(), tx.sender.length(), hash);
    return std::to_string(hash[0] % shardCount);
}

void AhmiyatChain::processPendingTxs() {
    std::lock_guard<std::mutex> lock(chainMutex);
    while (!pendingTxs.empty()) {
        Transaction tx = pendingTxs.front();
        pendingTxs.pop();
        std::vector<Transaction> txs = {tx};
        MemoryFragment mem("text", "memories/pending_" + tx.getHash() + ".txt", "Pending tx", tx.sender, 0);
        addBlock(txs, mem, tx.sender, shardStakes[tx.shardId][tx.sender]);
    }
}

void AhmiyatChain::addBlock(const std::vector<Transaction>& txs, const MemoryFragment& memory, std::string minerId, double stake) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (totalMined + blockReward > MAX_SUPPLY) {
        log("Max supply reached");
        return;
    }

    std::unordered_map<std::string, std::vector<Transaction>> shardTxs;
    for (auto tx : txs) {
        std::string shardId = assignShard(tx);
        tx.shardId = shardId;
        if (validateTransaction(tx, shardId)) {
            tx.signature = signTransaction(tx);
            if (tx.signature.empty()) {
                log("Failed to sign tx: " + tx.getHash());
                continue;
            }
            shardTxs[shardId].push_back(tx);
            processedTxs.insert(tx.signature);
        }
    }

    std::vector<std::thread> blockThreads;
    for (auto& [shardId, txsInShard] : shardTxs) {
        blockThreads.emplace_back([&, shardId, txsInShard]() {
            try {
                AhmiyatBlock newBlock(shards[shardId].size(), txsInShard, memory, 
                                     shards[shardId].empty() ? "0" : shards[shardId].back().getHash(), 
                                     shardDifficulties[shardId], stake, shardId);
                if (!validateBlock(newBlock)) {
                    log("Invalid block in shard " + shardId);
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(chainMutex);
                    shards[shardId].push_back(newBlock);
                    saveBlockToDB(newBlock);
                }

                double totalFee = 0.0;
                for (const auto& tx : txsInShard) {
                    shardBalances[shardId][tx.sender] -= (tx.amount + tx.fee);
                    shardBalances[shardId][tx.receiver] += tx.amount;
                    totalFee += tx.fee;
                }
                shardBalances[shardId][minerId] += blockReward + totalFee;
                if (stake > 0) shardBalances[shardId][minerId] += stakingReward;
                totalMined += blockReward;
                updateReward(shardId);
                broadcastBlock(newBlock, nodes[0]);
                compressState(shardId);
                adjustDifficultyDynamic(shardId);
            } catch (const std::exception& e) {
                log("Block error in shard " + shardId + ": " + e.what());
            }
        });
    }
    for (auto& t : blockThreads) t.join();
}

void AhmiyatChain::addNode(std::string nodeId, std::string ip, int port) {
    std::lock_guard<std::mutex> lock(chainMutex);
    Node newNode(nodeId, ip, port);
    nodes.push_back(newNode);
    dht.addPeer(newNode);
    log("Node added: " + nodeId + " (" + ip + ":" + std::to_string(port) + ")");
}

double AhmiyatChain::getBalance(std::string address, std::string shardId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    return shardBalances[shardId][address];
}

void AhmiyatChain::stakeCoins(std::string address, double amount, std::string shardId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (shardBalances[shardId][address] >= amount) {
        shardBalances[shardId][address] -= amount;
        shardStakes[shardId][address] += amount;
        log(address + " staked " + std::to_string(amount) + " AHM in shard " + shardId);
    } else {
        log("Insufficient balance to stake for " + address + " in shard " + shardId);
    }
}

void AhmiyatChain::adjustDifficultyDynamic(std::string shardId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    int activeNodes = nodes.size();
    if (shards[shardId].size() > 10) {
        uint64_t lastTenTime = shards[shardId].back().timestamp - shards[shardId][shards[shardId].size() - 10].timestamp;
        double avgStake = 0;
        for (const auto& block : shards[shardId]) avgStake += block.getStakeWeight();
        avgStake /= shards[shardId].size();
        if (lastTenTime < 60'000'000 || avgStake > 1000 || activeNodes > 10) shardDifficulties[shardId]++;
        else if (lastTenTime > 120'000'000 && shardDifficulties[shardId] > 1 && activeNodes < 5) shardDifficulties[shardId]--;
        log("Difficulty adjusted in shard " + shardId + " to: " + std::to_string(shardDifficulties[shardId]));
    }
}

void AhmiyatChain::startNodeListener(int port) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log("SSL_CTX creation failed");
        return;
    }

    if (SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "certs/key.pem", SSL_FILETYPE_PEM) <= 0) {
        log("Failed to load TLS certificates");
        SSL_CTX_free(ctx);
        return;
    }

    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        log("Socket creation failed");
        SSL_CTX_free(ctx);
        return;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    if (bind(serverSock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        log("Bind failed on port " + std::to_string(port));
        close(serverSock);
        SSL_CTX_free(ctx);
        return;
    }
    if (listen(serverSock, 10) < 0) {
        log("Listen failed on port " + std::to_string(port));
        close(serverSock);
        SSL_CTX_free(ctx);
        return;
    }
    log("Node listening on port " + std::to_string(port) + " with TLS");

    std::vector<std::thread> listenerThreads;
    while (true) {
        int clientSock = accept(serverSock, nullptr, nullptr);
        if (clientSock < 0) {
            log("Accept failed");
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSock);

        listenerThreads.emplace_back([&, clientSock, ssl]() {
            try {
                if (SSL_accept(ssl) <= 0) {
                    log("TLS handshake failed");
                    SSL_free(ssl);
                    close(clientSock);
                    return;
                }

                char buffer[4096] = {0};
                ssize_t bytesRead = SSL_read(ssl, buffer, 4096);
                if (bytesRead > 0) {
                    std::string data(buffer, bytesRead);
                    syncChain(data);
                    processPendingTxs();
                }
                SSL_free(ssl);
                close(clientSock);
            } catch (const std::exception& e) {
                log("Listener error: " + std::string(e.what()));
                SSL_free(ssl);
                close(clientSock);
            }
        });

        for (auto it = listenerThreads.begin(); it != listenerThreads.end();) {
            if (it->joinable()) {
                it->join();
                it = listenerThreads.erase(it);
            } else {
                ++it;
            }
        }
    }
    close(serverSock);
    SSL_CTX_free(ctx);
}

void AhmiyatChain::stressTest(int numBlocks) {
    Wallet wallet;
    registerPublicKey(wallet.publicKey, wallet.publicKey);
    std::vector<std::thread> testThreads;
    for (int i = 0; i < numBlocks; i++) {
        testThreads.emplace_back([&, i]() {
            std::vector<Transaction> txs = {Transaction(wallet.publicKey, "test" + std::to_string(i), 1.0)};
            MemoryFragment mem("text", "memories/test" + std::to_string(i) + ".txt", "Test block", wallet.publicKey, 0);
            addBlock(txs, mem, wallet.publicKey, shardStakes[assignShard(txs[0])][wallet.publicKey]);
        });
    }
    for (auto& t : testThreads) t.join();
    log("Stress test completed: " + std::to_string(numBlocks) + " blocks added across shards");
}

void AhmiyatChain::proposeUpgrade(std::string proposerId, std::string description) {
    std::lock_guard<std::mutex> lock(chainMutex);
    std::string proposalId = proposerId + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    governanceProposals[proposalId] = {description, 0, {}};
    log("Proposal " + proposalId + " submitted: " + description);
}

void AhmiyatChain::voteForUpgrade(std::string voterId, std::string proposalId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (!governanceProposals.count(proposalId)) {
        log("Invalid proposal ID: " + proposalId);
        return;
    }
    if (governanceProposals[proposalId].voters.count(voterId)) {
        log(voterId + " already voted for " + proposalId);
        return;
    }
    double totalStake = 0;
    for (const auto& [shardId, stakes] : shardStakes) {
        if (stakes.count(voterId)) totalStake += stakes.at(voterId);
    }
    governanceProposals[proposalId].votes += totalStake;
    governanceProposals[proposalId].voters.insert(voterId);
    log(voterId + " voted for " + proposalId + " with " + std::to_string(totalStake) + " stake");
}

std::string AhmiyatChain::getShardStatus(std::string shardId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    std::stringstream ss;
    ss << "Shard " << shardId << ":\n";
    ss << "Blocks: " << shards[shardId].size() << "\n";
    ss << "Total Balance: ";
    double total = 0;
    for (const auto& [addr, bal] : shardBalances[shardId]) total += bal;
    ss << total << " AHM\n";
    ss << "Difficulty: " << shardDifficulties[shardId] << "\n";
    ss << "Nodes: " << nodes.size() << "\n";
    return ss.str();
}

void AhmiyatChain::handleCrossShardTx(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(chainMutex);
    std::string fromShard = tx.shardId;
    std::string toShard = assignShard(Transaction(tx.receiver, tx.sender, 0));
    if (fromShard != toShard) {
        if (shardBalances[fromShard][tx.sender] >= tx.amount + tx.fee) {
            shardBalances[fromShard][tx.sender] -= (tx.amount + tx.fee);
            shardBalances[toShard][tx.receiver] += tx.amount;
            log("Cross-shard tx from " + fromShard + " to " + toShard + ": " + std::to_string(tx.amount) + " AHM");
            Transaction confirmTx(tx.receiver, tx.sender, 0.0, 0.0, "CROSS_SHARD_CONFIRM", toShard);
            confirmTx.signature = signTransaction(confirmTx);
            addPendingTx(confirmTx);
        } else {
            log("Cross-shard tx failed: Insufficient balance in " + fromShard);
        }
    }
}

void AhmiyatChain::addPendingTx(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(chainMutex);
    pendingTxs.push(tx);
    log("Added pending tx: " + tx.getHash());
}

void AhmiyatChain::faucet(std::string address, double amount, std::string shardId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (totalMined + amount <= MAX_SUPPLY) {
        shardBalances[shardId][address] += amount;
        totalMined += amount;
        log("Faucet: " + address + " received " + std::to_string(amount) + " AHM in shard " + shardId);
    } else {
        log("Faucet failed: Max supply reached");
    }
}

void AhmiyatChain::registerPublicKey(const std::string& address, const std::string& pubKey) {
    std::lock_guard<std::mutex> lock(chainMutex);
    publicKeys[address] = pubKey;
    log("Registered public key for " + address);
}

std::optional<std::vector<AhmiyatBlock>> AhmiyatChain::getBlocks(std::string shardId) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (shards.count(shardId)) {
        return shards[shardId];
    }
    return std::nullopt;
}
