#ifndef SAFEZONE_H
#define SAFEZONE_H

#include <string>
#include <vector>

std::vector<unsigned char> sha512(const std::vector<unsigned char> &d);
std::string toHex(const std::vector<unsigned char> &d);
std::vector<unsigned char> hexToBytes(const std::string &hex);
std::string get_keys_file_path();
std::string getMountPointFromConfig();
void generateKeys(const std::string &keysFile, const std::string &masterFile);
bool verifyIntegrity(const std::string &keysFile, const std::string &masterFile);
void aesCrypt(const std::vector<unsigned char> &k, const std::vector<unsigned char> &i, std::vector<unsigned char> &o, bool enc);

#endif

