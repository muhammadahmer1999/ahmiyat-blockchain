#include "dht.h"
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdexcept>
#include <microhttpd.h>

extern void log(const std::string& message);

Node::Node(std::string id, std::string ipAddr, int p) : nodeId(id), ip(ipAddr), port(p) {}

std::string DHT::hashNodeId(const std::string& nodeId) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)nodeId.c_str(), nodeId.length(), hash);
    return std::string((char*)hash, SHA256_DIGEST_LENGTH);
}

void DHT::addPeer(const Node& node) {
    std::lock_guard<std::mutex> lock(dhtMutex);
    peers[hashNodeId(node.nodeId)] = node;
    log("Peer added to DHT: " + node.nodeId);
}

std::vector<Node> DHT::findPeers(const std::string& targetId, int maxPeers) {
    std::lock_guard<std::mutex> lock(dhtMutex);
    std::vector<std::pair<std::string, Node>> sortedPeers;
    std::string targetHash = hashNodeId(targetId);
    for (const auto& peer : peers) {
        sortedPeers.push_back({peer.first, peer.second});
    }
    std::sort(sortedPeers.begin(), sortedPeers.end(), 
              [&](const auto& a, const auto& b) { 
                  return memcmp(a.first.c_str(), targetHash.c_str(), SHA256_DIGEST_LENGTH) < 
                         memcmp(b.first.c_str(), targetHash.c_str(), SHA256_DIGEST_LENGTH); 
              });
    std::vector<Node> closest;
    for (int i = 0; i < std::min(maxPeers, (int)sortedPeers.size()); i++) {
        closest.push_back(sortedPeers[i].second);
    }
    return closest;
}

void DHT::bootstrap(const std::string& bootstrapIp, int bootstrapPort) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log("Bootstrap socket creation failed");
        return;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bootstrapPort);
    if (inet_pton(AF_INET, bootstrapIp.c_str(), &addr.sin_addr) <= 0) {
        log("Invalid bootstrap IP: " + bootstrapIp);
        close(sock);
        return;
    }

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
        std::string msg = "BOOTSTRAP_REQUEST";
        send(sock, msg.c_str(), msg.length(), 0);
        char buffer[1024] = {0};
        read(sock, buffer, 1024);
        log("Bootstrapped with peers: " + std::string(buffer));
    } else {
        log("Bootstrap connection failed to " + bootstrapIp + ":" + std::to_string(bootstrapPort));
    }
    close(sock);
}

bool DHT::punchHole(const std::string& targetIp, int targetPort) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log("Hole punch socket creation failed");
        return false;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(targetPort);
    if (inet_pton(AF_INET, targetIp.c_str(), &addr.sin_addr) <= 0) {
        log("Invalid target IP: " + targetIp);
        close(sock);
        return false;
    }

    std::string msg = "PUNCH";
    sendto(sock, msg.c_str(), msg.length(), 0, (sockaddr*)&addr, sizeof(addr));
    log("Hole punched to " + targetIp + ":" + std::to_string(targetPort));
    close(sock);
    return true;
}
