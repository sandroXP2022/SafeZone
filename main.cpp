#include <ncurses.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/aes.h>
#include "safezone.h"

namespace fs = std::filesystem;
static constexpr char MASTER_NAME[] = "master.key";

bool fileExists(const std::string &p) {
    struct stat st;
    return stat(p.c_str(), &st) == 0;
}

WINDOW *createWin(int h, int w) {
    int maxY, maxX;
    getmaxyx(stdscr, maxY, maxX);
    WINDOW *win = newwin(h, w, std::max(0,(maxY - h) / 2), std::max(0,(maxX - w) / 2));
    wbkgd(win, COLOR_PAIR(3));
    box(win, 0, 0);
    return win;
}

static void trimTrailingNulls(std::string &s) {
    while (!s.empty() && s.back() == '\0') s.pop_back();
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
    std::ofstream ofs(d + "/" + std::string(f) + ".key", std::ios::binary | std::ios::trunc);
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
    char buf[256];
    while (true) {
        mvwgetnstr(w, lineY++, 2, buf, 255);
        if (!*buf) break;
        c += std::string(buf) + "\n";
    }
    noecho();
    curs_set(0);
    while (c.size() % AES_BLOCK_SIZE) c.push_back('\0');
    std::vector<unsigned char> i(c.begin(), c.end()), o;
    aesCrypt(k, i, o, true);
    std::ofstream ofs(d + "/" + std::string(f) + ".key", std::ios::binary | std::ios::trunc);
    ofs.write((char *)o.data(), o.size());
}

void viewFile(WINDOW *w, const std::string &d, const std::vector<unsigned char> &k) {
    werase(w);
    box(w, 0, 0);
    mvwprintw(w, 1, 2, "Available .key files:");
    std::vector<std::string> files;
    for (auto &p : fs::directory_iterator(d)) {
        if (p.path().extension() == ".key" && p.path().filename().string() != MASTER_NAME)
            files.push_back(p.path().filename().string());
    }
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
        werase(w);
        box(w,0,0);
        mvwprintw(w,1,2,"Available .key files:");
        for (int i = 0; i < (int)files.size() && i < h - 6; i++) {
            if (i == hl) wattron(w, COLOR_PAIR(1));
            mvwprintw(w, 3 + i, 4, files[i].c_str());
            if (i == hl) wattroff(w, COLOR_PAIR(1));
        }
        mvwprintw(w, h - 2, 2, "Use Arrows+Enter  Esc to back");
        wrefresh(w);
        int c = wgetch(w);
        if (c == KEY_UP && hl > 0) hl--;
        else if (c == KEY_DOWN && hl < (int)files.size() - 1) hl++;
        else if (c == 10) break;
        else if (c == 27) return;
    }
    std::ifstream f(d + "/" + files[hl], std::ios::binary);
    std::vector<unsigned char> enc((std::istreambuf_iterator<char>(f)), {});
    std::vector<unsigned char> dec;
    if (enc.empty()) {
        mvwprintw(w,3,2,"Empty file.");
        wrefresh(w); wgetch(w); return;
    }
    aesCrypt(k, enc, dec, false);
    std::string content((char*)dec.data(), dec.size());
    trimTrailingNulls(content);
    werase(w);
    box(w, 0, 0);
    mvwprintw(w, 1, 2, "File: %s", files[hl].c_str());
    if (content.find(':') != std::string::npos && content.find("\n") == std::string::npos) {
        auto pos = content.find(':');
        std::string user = content.substr(0, pos);
        std::string pass = content.substr(pos + 1);
        mvwprintw(w, 3, 4, "User: %s", user.c_str());
        mvwprintw(w, 4, 4, "Password: %s", pass.c_str());
    } else {
        mvwprintw(w, 3, 2, "--- Content ---");
        int line = 5;
        std::istringstream iss(content);
        std::string ln;
        int hgt, widt;
        getmaxyx(w, hgt, widt);
        while (std::getline(iss, ln) && line < hgt - 1)
            mvwprintw(w, line++, 2, "%s", ln.c_str());
    }
    wrefresh(w);
    wgetch(w);
}

int main() {
    std::string keysPath = get_keys_file_path();
    std::string mpt = getMountPointFromConfig();
    if (mpt.empty()) {
        std::cerr << "Failed to mount drive from config or no DRIVE set. Check ~/.config/safezone/config. mount may require root.\n";
        return 1;
    }

    bool keysExist = fileExists(keysPath), masterExist = fileExists(mpt + "/" + MASTER_NAME);
    if (keysExist != masterExist) {
        std::cerr << "Integrity error: Only one of keys file or master exists.\n";
        return 1;
    }
    if (!keysExist && !masterExist) {
        generateKeys(keysPath, mpt + "/" + MASTER_NAME);
    } else if (!verifyIntegrity(keysPath, mpt + "/" + MASTER_NAME)) {
        std::cerr << "Integrity verification failed.\n";
        return 1;
    }

    std::ifstream kf(keysPath);
    std::string line;
    std::getline(kf, line);
    if (line.empty()) {
        std::cerr << "No key found in keys file.\n";
        return 1;
    }
    std::vector<unsigned char> aesKey = hexToBytes(line);
    if (aesKey.size() != 32) {
        std::cerr << "Invalid key length.\n";
        return 1;
    }

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

    std::vector<std::string> menu = {"SafeZone 0.1.0", "Create File", "View File", "Exit"};
    int hl = 1;
    while (true) {
        int h = (int)menu.size() + 8, w = 60;
        WINDOW *win = createWin(h, w);
        keypad(win, TRUE);
        for (int i = 0; i < (int)menu.size(); ++i) {
            if (i == hl) wattron(win, COLOR_PAIR(1));
            mvwprintw(win, 2 + i, 2, "%s", menu[i].c_str());
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
                        mvwprintw(win, 2 + j, 2, "%s", sub[j].c_str());
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
    system(("umount " + mpt + " 2>/dev/null").c_str());
    return 0;
}

