#include "wallet.h"
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <stdexcept>
#include <microhttpd.h>

Wallet::Wallet() {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) throw std::runtime_error("Wallet key generation failed");
    EC_KEY_generate_key(key);

    const EC_POINT* pubKey = EC_KEY_get0_public_key(key);
    char* pubHex = EC_POINT_point2hex(EC_GROUP_new_by_curve_name(NID_secp256k1), 
                                      pubKey, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    if (!pubHex) {
        EC_KEY_free(key);
        throw std::runtime_error("Public key generation failed");
    }
    publicKey = std::string(pubHex);
    OPENSSL_free(pubHex);

    const BIGNUM* privKey = EC_KEY_get0_private_key(key);
    char* privHex = BN_bn2hex(privKey);
    if (!privHex) {
        EC_KEY_free(key);
        throw std::runtime_error("Private key generation failed");
    }
    privateKey = std::string(privHex);
    OPENSSL_free(privHex);

    EC_KEY_free(key);
}
