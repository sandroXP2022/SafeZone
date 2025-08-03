#include <ncurses.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <random>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <iomanip>

namespace fs = std::filesystem;
static constexpr char KEYS_FILE[] = "/.keys";
static constexpr char MASTER_NAME[] = "master.key";

bool fileExists(const std::string &p) {
    struct stat st;
    return stat(p.c_str(), &st) == 0;
}

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
    for (auto c : d) oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}

std::string getMountPointFromConfig() {
    std::string cfg = std::string(getenv("HOME")) + "/.config/safezone/config";
    std::ifstream f(cfg);
    std::string line;
    std::string drive;
    while (std::getline(f, line)) {
        if (line.rfind("DRIVE=", 0) == 0) {
            drive = line.substr(6);
            break;
        }
    }
    if (drive.empty()) return "";
    std::string mpt = "/mnt/safezone";
    fs::create_directories(mpt);
    std::string cmd = "mount " + drive + " " + mpt;
    if (system(cmd.c_str()) != 0) return "";
    return mpt;
}

void generateKeys(const std::string &keysFile, const std::string &masterFile) {
    std::ofstream kf(keysFile);
    std::ofstream mf(masterFile);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (int i = 0; i < 3; i++) {
        std::vector<unsigned char> key(32);
        for (auto &b : key) b = dist(gen);
        std::string keyStr(key.begin(), key.end());
        kf << keyStr << "\n";
        auto hash = sha512(key);
        mf << toHex(hash) << "\n";
    }
}

bool verifyIntegrity(const std::string &keysFile, const std::string &masterFile) {
    std::ifstream kf(keysFile);
    std::ifstream mf(masterFile);
    std::vector<std::string> keys, hashes;
    for (std::string l; std::getline(kf, l);) keys.push_back(l);
    for (std::string l; std::getline(mf, l);) hashes.push_back(l);
    if (keys.size() != 3 || hashes.size() != 3) return false;
    for (int i = 0; i < 3; i++) {
        std::vector<unsigned char> k(keys[i].begin(), keys[i].end());
        if (toHex(sha512(k)) != hashes[i]) return false;
    }
    return true;
}

void aesCrypt(const std::vector<unsigned char> &k, const std::vector<unsigned char> &i, std::vector<unsigned char> &o, bool enc) {
    AES_KEY key;
    if (enc)
        AES_set_encrypt_key(k.data(), 256, &key);
    else
        AES_set_decrypt_key(k.data(), 256, &key);
    size_t n = i.size() / AES_BLOCK_SIZE;
    o.resize(n * AES_BLOCK_SIZE);
    for (size_t idx = 0; idx < n; idx++)
        AES_ecb_encrypt(i.data() + idx * AES_BLOCK_SIZE, o.data() + idx * AES_BLOCK_SIZE, &key, enc ? AES_ENCRYPT : AES_DECRYPT);
}

WINDOW *createWin(int h, int w) {
    int maxY, maxX;
    getmaxyx(stdscr, maxY, maxX);
    WINDOW *win = newwin(h, w, (maxY - h) / 2, (maxX - w) / 2);
    wbkgd(win, COLOR_PAIR(3));
    box(win, 0, 0);
    return win;
}

void createCredentials(WINDOW *w, const std::string &d, const std::vector<unsigned char> &k) {
    werase(w);
    box(w, 0, 0);
    mvwprintw(w, 2, 2, "Filename:");
    mvwprintw(w, 4, 2, "User:");
    mvwprintw(w, 6, 2, "Password:");
    wrefresh(w);
    echo();
    curs_set(1);
    char f[64], u[64], p[64];
    mvwgetnstr(w, 2, 12, f, 63);
    mvwgetnstr(w, 4, 12, u, 63);
    mvwgetnstr(w, 6, 12, p, 63);
    noecho();
    curs_set(0);
    std::string dt = std::string(u) + ":" + p;
    while (dt.size() % AES_BLOCK_SIZE) dt.push_back('\0');
    std::vector<unsigned char> i(dt.begin(), dt.end()), o;
    aesCrypt(k, i, o, true);
    std::ofstream ofs(d + "/" + f + ".key", std::ios::binary);
    ofs.write((char *)o.data(), o.size());
}

void createOther(WINDOW *w, const std::string &d, const std::vector<unsigned char> &k) {
    werase(w);
    box(w, 0, 0);
    mvwprintw(w, 2, 2, "Filename:");
    mvwprintw(w, 4, 2, "Content(blank line ends):");
    wrefresh(w);
    echo();
    curs_set(1);
    char f[64];
    mvwgetnstr(w, 2, 12, f, 63);
    std::string c;
    int lineY = 6;
    char buf[128];
    while (true) {
        mvwgetnstr(w, lineY++, 2, buf, 127);
        if (!*buf) break;
        c += std::string(buf) + "\n";
    }
    noecho();
    curs_set(0);
    while (c.size() % AES_BLOCK_SIZE) c.push_back('\0');
    std::vector<unsigned char> i(c.begin(), c.end()), o;
    aesCrypt(k, i, o, true);
    std::ofstream ofs(d + "/" + f + ".key", std::ios::binary);
    ofs.write((char *)o.data(), o.size());
}

void viewFile(WINDOW *w, const std::string &d, const std::vector<unsigned char> &k) {
    werase(w);
    box(w, 0, 0);
    mvwprintw(w, 1, 2, "Available .key files:");
    std::vector<std::string> files;
    for (auto &p : fs::directory_iterator(d))
        if (p.path().extension() == ".key" && p.path().filename() != MASTER_NAME)
            files.push_back(p.path().filename().string());
    if (files.empty()) {
        mvwprintw(w, 3, 2, "No files found.");
        wrefresh(w);
        wgetch(w);
        return;
    }
    int h, wid;
    getmaxyx(w, h, wid);
    int hl = 0;
    keypad(w, TRUE);
    while (true) {
        for (int i = 0; i < (int)files.size() && i < h - 4; i++) {
            if (i == hl) wattron(w, COLOR_PAIR(1));
            mvwprintw(w, 3 + i, 4, files[i].c_str());
            if (i == hl) wattroff(w, COLOR_PAIR(1));
        }
        wrefresh(w);
        int c = wgetch(w);
        if (c == KEY_UP && hl > 0) hl--;
        else if (c == KEY_DOWN && hl < (int)files.size() - 1) hl++;
        else if (c == 10) break;
        else if (c == 27) return;
    }
    std::ifstream f(d + "/" + files[hl], std::ios::binary);
    std::vector<unsigned char> enc((std::istreambuf_iterator<char>(f)), {}), dec;
    aesCrypt(k, enc, dec, false);
    std::string content((char *)dec.data(), dec.size());
    werase(w);
    box(w, 0, 0);
    mvwprintw(w, 1, 2, "File:%s", files[hl].c_str());
    if (content.find(':') != std::string::npos && content.find("\n") == std::string::npos) {
        auto pos = content.find(':');
        mvwprintw(w, 3, 4, "User:%s", content.substr(0, pos).c_str());
        mvwprintw(w, 4, 4, "Password:%s", content.substr(pos + 1).c_str());
    } else {
        mvwprintw(w, 3, 2, "--- Content ---");
        int line = 5;
        std::istringstream iss(content);
        std::string ln;
        while (std::getline(iss, ln) && line < h - 1)
            mvwprintw(w, line++, 2, ln.c_str());
    }
    wrefresh(w);
    wgetch(w);
}

int main() {
    std::string mpt = getMountPointFromConfig();
    if (mpt.empty()) {
        std::cerr << "Failed to mount drive from config." << std::endl;
        return 1;
    }

    bool keysExist = fileExists(KEYS_FILE), masterExist = fileExists(mpt + "/" + MASTER_NAME);
    if (keysExist != masterExist) {
        std::cerr << "Integrity error: Only one key file exists." << std::endl;
        return 1;
    }
    if (!keysExist && !masterExist) {
        generateKeys(KEYS_FILE, mpt + "/" + MASTER_NAME);
    } else if (!verifyIntegrity(KEYS_FILE, mpt + "/" + MASTER_NAME)) {
        std::cerr << "Integrity verification failed." << std::endl;
        return 1;
    }

    std::ifstream kf(KEYS_FILE);
    std::string line;
    std::getline(kf, line);
    std::vector<unsigned char> aesKey(line.begin(), line.end());

    initscr();
    start_color();
    use_default_colors();
    init_pair(1, COLOR_BLACK, COLOR_CYAN);
    init_pair(2, COLOR_WHITE, COLOR_BLUE);
    init_pair(3, COLOR_BLACK, COLOR_WHITE);
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    bkgd(COLOR_PAIR(2));
    refresh();

    std::vector<std::string> menu = {"SafeZone 0.0.1", "Create File", "View File", "Exit"};
    int hl = 1;
    while (true) {
        int h = menu.size() + 8, w = 50;
        WINDOW *win = createWin(h, w);
        keypad(win, TRUE);
        for (int i = 0; i < (int)menu.size(); ++i) {
            if (i == hl) wattron(win, COLOR_PAIR(1));
            mvwprintw(win, 2 + i, 2, menu[i].c_str());
            if (i == hl) wattroff(win, COLOR_PAIR(1));
        }
        mvwprintw(win, h - 2, 2, "Use Arrows+Enter");
        wrefresh(win);
        int c = wgetch(win);
        if (c == KEY_UP) hl = (hl + menu.size() - 1) % menu.size();
        else if (c == KEY_DOWN) hl = (hl + 1) % menu.size();
        else if (c == 10) {
            if (hl == 3) {
                delwin(win);
                break;
            }
            if (hl == 1) {
                std::vector<std::string> sub = {"Credentials", "Other", "Back"};
                int sh = 0;
                while (true) {
                    werase(win);
                    box(win, 0, 0);
                    for (int j = 0; j < (int)sub.size(); j++) {
                        if (j == sh) wattron(win, COLOR_PAIR(1));
                        mvwprintw(win, 2 + j, 2, sub[j].c_str());
                        if (j == sh) wattroff(win, COLOR_PAIR(1));
                    }
                    mvwprintw(win, (int)sub.size() + 4, 2, "Use Arrows+Enter");
                    wrefresh(win);
                    int sc = wgetch(win);
                    if (sc == KEY_UP) sh = (sh + sub.size() - 1) % sub.size();
                    else if (sc == KEY_DOWN) sh = (sh + 1) % sub.size();
                    else if (sc == 10) {
                        if (sh == 2) break;
                        if (sh == 0) createCredentials(win, mpt, aesKey);
                        if (sh == 1) createOther(win, mpt, aesKey);
                    }
                }
            }
            if (hl == 2) viewFile(win, mpt, aesKey);
        }
        delwin(win);
    }
    endwin();
    system(("umount " + mpt).c_str());
    return 0;
}

