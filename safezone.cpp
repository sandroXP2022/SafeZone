#include "safezone.h"
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <iostream>
#include <filesystem>
#include <unistd.h>

namespace fs = std::filesystem;

std::vector<unsigned char> sha512(const std::vector<unsigned char> &d) {
    std::vector<unsigned char> r(SHA512_DIGEST_LENGTH);
    SHA512_CTX c;
    SHA512_Init(&c);
    SHA512_Update(&c, d.data(), d.size());
    SHA512_Final(r.data(), &c);
    return r;
}

std::string toHex(const std::vector<unsigned char> &d) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : d) oss << std::setw(2) << (int)c;
    return oss.str();
}

std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte;
        std::istringstream iss(hex.substr(i,2));
        iss >> std::hex >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

std::string get_keys_file_path() {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    return std::string(home ? home : "/tmp") + "/.keys";
}

std::string getMountPointFromConfig() {
    const char *home = getenv("HOME");
    std::string cfg = std::string(home ? home : "/tmp") + "/.config/safezone/config";
    std::ifstream f(cfg);
    std::string line;
    std::string drive;
    while (f && std::getline(f, line)) {
        if (line.rfind("DRIVE=", 0) == 0) {
            drive = line.substr(6);
            break;
        }
    }
    if (drive.empty()) return "";
    std::string mpt = "/mnt/safezone";
    fs::create_directories(mpt);
    std::string cmd = "mount " + drive + " " + mpt + " 2>/dev/null";
    if (system(cmd.c_str()) != 0) {
        struct stat st;
        if (stat(mpt.c_str(), &st) != 0) return "";
    }
    return mpt;
}

void generateKeys(const std::string &keysFile, const std::string &masterFile) {
    std::ofstream kf(keysFile, std::ios::out | std::ios::trunc);
    std::ofstream mf(masterFile, std::ios::out | std::ios::trunc);
    if (!kf || !mf) return;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (int i = 0; i < 3; i++) {
        std::vector<unsigned char> key(32);
        for (auto &b : key) b = static_cast<unsigned char>(dist(gen));
        kf << toHex(key) << "\n";
        auto hash = sha512(key);
        mf << toHex(hash) << "\n";
    }
    kf.close();
    mf.close();
    chmod(keysFile.c_str(), S_IRUSR | S_IWUSR);
    chmod(masterFile.c_str(), S_IRUSR | S_IWUSR);
}

bool verifyIntegrity(const std::string &keysFile, const std::string &masterFile) {
    std::ifstream kf(keysFile);
    std::ifstream mf(masterFile);
    if (!kf || !mf) return false;
    std::vector<std::string> keys, hashes;
    for (std::string l; std::getline(kf, l);) {
        if (!l.empty()) keys.push_back(l);
    }
    for (std::string l; std::getline(mf, l);) {
        if (!l.empty()) hashes.push_back(l);
    }
    if (keys.size() != 3 || hashes.size() != 3) return false;
    for (int i = 0; i < 3; i++) {
        auto keyBytes = hexToBytes(keys[i]);
        if (toHex(sha512(keyBytes)) != hashes[i]) return false;
    }
    return true;
}

void aesCrypt(const std::vector<unsigned char> &k, const std::vector<unsigned char> &i, std::vector<unsigned char> &o, bool enc) {
    AES_KEY key;
    if (k.size() != 32) {
        o.clear();
        return;
    }
    if (enc)
        AES_set_encrypt_key(k.data(), 256, &key);
    else
        AES_set_decrypt_key(k.data(), 256, &key);
    size_t n = i.size() / AES_BLOCK_SIZE;
    o.resize(n * AES_BLOCK_SIZE);
    for (size_t idx = 0; idx < n; idx++)
        AES_ecb_encrypt(i.data() + idx * AES_BLOCK_SIZE, o.data() + idx * AES_BLOCK_SIZE, &key, enc ? AES_ENCRYPT : AES_DECRYPT);
}

