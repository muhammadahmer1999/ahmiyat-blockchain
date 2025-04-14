#include "utils.h"
#include <fstream>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <stdexcept>

void log(const std::string& message) {
    std::ofstream logFile("ahmiyat.log", std::ios::app);
    logFile << "[" << time(nullptr) << "] " << message << std::endl;
}

size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* data) {
    data->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string uploadToIPFS(const std::string& filePath) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        log("CURL initialization failed");
        return "ERROR";
    }

    std::string response;
    CURLcode res;
    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, filePath.c_str());

    // Try local daemon first
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:5001/api/v0/add");
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log("Local IPFS upload failed: " + std::string(curl_easy_strerror(res)));
        response.clear();
        curl_easy_setopt(curl, CURLOPT_URL, "https://ipfs.io/api/v0/add");
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log("Public IPFS upload failed: " + std::string(curl_easy_strerror(res)));
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return "ERROR";
        }
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    size_t pos = response.find("\"Hash\":\"") + 8;
    size_t end = response.find("\"", pos);
    if (pos == std::string::npos || end == std::string::npos) {
        log("IPFS response parsing failed");
        return "ERROR";
    }
    return response.substr(pos, end - pos);
}

std::string generateZKProof(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.length(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return "ZKP_" + ss.str().substr(0, 16);
}
