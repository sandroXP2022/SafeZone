#include <ncurses.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <random>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

namespace fs = std::filesystem;
static const char* DRIVE_SUBDIR = "safezone";
static const char* MASTER_NAME = "master.key";

bool fileExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

std::vector<unsigned char> sha512(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> digest(SHA512_DIGEST_LENGTH);
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, data.data(), data.size());
    SHA512_Final(digest.data(), &ctx);
    return digest;
}

std::vector<unsigned char> readMasterKey(const std::string& path) {
    std::ifstream in(path);
    std::vector<unsigned char> raw;
    std::string hex;
    while (std::getline(in, hex)) {
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
            raw.push_back((unsigned char)std::stoul(hex.substr(i,2), nullptr, 16));
    }
    return sha512(raw);
}

void aesEncrypt(const std::vector<unsigned char>& key,
                const std::vector<unsigned char>& in,
                std::vector<unsigned char>& out) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key.data(), 256, &aesKey);
    size_t blocks = in.size() / AES_BLOCK_SIZE;
    out.resize(blocks * AES_BLOCK_SIZE);
    for (size_t i = 0; i < blocks; ++i)
        AES_ecb_encrypt(in.data() + i*AES_BLOCK_SIZE,
                        out.data() + i*AES_BLOCK_SIZE,
                        &aesKey, AES_ENCRYPT);
}

void aesDecrypt(const std::vector<unsigned char>& key,
                const std::vector<unsigned char>& in,
                std::vector<unsigned char>& out) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key.data(), 256, &aesKey);
    size_t blocks = in.size() / AES_BLOCK_SIZE;
    out.resize(blocks * AES_BLOCK_SIZE);
    for (size_t i = 0; i < blocks; ++i)
        AES_ecb_encrypt(in.data() + i*AES_BLOCK_SIZE,
                        out.data() + i*AES_BLOCK_SIZE,
                        &aesKey, AES_DECRYPT);
}

WINDOW* createWindow(int height, int width) {
    int maxY, maxX;
    getmaxyx(stdscr, maxY, maxX);
    int y = (maxY - height) / 2;
    int x = (maxX - width) / 2;
    WINDOW* w = newwin(height, width, y, x);
    wbkgd(w, COLOR_PAIR(3));
    box(w, 0, 0);
    return w;
}

void createCredentials(WINDOW* win, const std::string& dir, const std::vector<unsigned char>& key) {
    werase(win); box(win, 0, 0);
    int y = 2;
    mvwprintw(win, y, 2, "Filename: ");
    mvwprintw(win, y+2, 2, "User:     ");
    mvwprintw(win, y+4, 2, "Password: ");
    mvwprintw(win, y+6, 2, "Press ENTER to save");
    wrefresh(win);

    echo(); curs_set(1);
    char fname[128], user[128], pass[128];
    mvwgetnstr(win, y, 12, fname, 50);
    mvwgetnstr(win, y+2, 12, user, 50);
    mvwgetnstr(win, y+4, 12, pass, 50);
    noecho(); curs_set(0);

    std::string data = std::string(user) + ":" + pass;
    while (data.size() % AES_BLOCK_SIZE) data.push_back('\0');
    std::vector<unsigned char> in(data.begin(), data.end()), out;
    aesEncrypt(key, in, out);

    std::ofstream f(dir + "/" + fname + ".key", std::ios::binary);
    f.write((char*)out.data(), out.size()); f.close();

    mvwprintw(win, y+8, 2, "Saved as %s.key", fname);
    wrefresh(win); wgetch(win);
}

void createOther(WINDOW* win, const std::string& dir, const std::vector<unsigned char>& key) {
    werase(win); box(win, 0, 0);
    int y = 2;
    mvwprintw(win, y, 2, "Filename:         ");
    mvwprintw(win, y+2, 2, "Content (end blank line):");
    wrefresh(win);

    echo(); curs_set(1);
    char fname[128]; mvwgetnstr(win, y, 12, fname, 50);
    std::string content;
    int lineY = y+4;
    char buf[256];
    while (true) {
        mvwgetnstr(win, lineY, 2, buf, 80);
        if (!*buf) break;
        content += std::string(buf) + "\n";
        lineY++;
    }
    noecho(); curs_set(0);

    while (content.size() % AES_BLOCK_SIZE) content.push_back('\0');
    std::vector<unsigned char> in(content.begin(), content.end()), out;
    aesEncrypt(key, in, out);

    std::ofstream f(dir + "/" + fname + ".key", std::ios::binary);
    f.write((char*)out.data(), out.size()); f.close();

    mvwprintw(win, lineY+1, 2, "Saved as %s.key", fname);
    wrefresh(win); wgetch(win);
}

void viewFile(WINDOW* win, const std::string& dir, const std::vector<unsigned char>& key) {
    werase(win); box(win,0,0);
    mvwprintw(win,1,2,"Available .key files:");
    std::vector<std::string> files;
    for(auto& p:fs::directory_iterator(dir)){
        if(p.path().extension()==".key" && p.path().filename()!=MASTER_NAME)
            files.push_back(p.path().filename().string());
    }
    if(files.empty()) { mvwprintw(win,3,2,"No files found."); wrefresh(win); wgetch(win); return; }

    int h,w; getmaxyx(win,h,w);
    int start=0, hl=0, display=h-4;
    keypad(win,TRUE);
    while(true){
        for(int i=0;i<std::min((int)files.size()-start,display);++i){
            if(i==hl) wattron(win,COLOR_PAIR(1));
            mvwprintw(win,3+i,4,files[start+i].c_str());
            if(i==hl) wattroff(win,COLOR_PAIR(1));
        }
        wrefresh(win);
        int c=wgetch(win);
        if(c==KEY_UP && hl>0) hl--;
        else if(c==KEY_DOWN && hl<display-1 && start+hl+1<files.size()) hl++;
        else if(c==KEY_NPAGE && start+display<files.size()) start+=display;
        else if(c==KEY_PPAGE && start>=display) start-=display;
        else if(c==10) break;
        else if(c==27) return;
    }

    std::ifstream f(dir+"/"+files[start+hl],std::ios::binary);
    std::vector<unsigned char> enc((std::istreambuf_iterator<char>(f)),{}), dec;
    aesDecrypt(key,enc,dec);
    std::string content((char*)dec.data(),dec.size());

    werase(win); box(win,0,0);
    mvwprintw(win,1,2,"File: %s",files[start+hl].c_str());
    if(content.find(':')!=std::string::npos && content.find("\n")==std::string::npos){
        auto pos=content.find(':');
        mvwprintw(win,3,4,"User: %s",content.substr(0,pos).c_str());
        mvwprintw(win,4,4,"Password: %s",content.substr(pos+1).c_str());
    } else {
        mvwprintw(win,3,2,"--- Content ---");
        int line=5;
        std::istringstream iss(content);
        std::string ln;
        while(std::getline(iss,ln) && line<h-1) mvwprintw(win,line++,2,ln.c_str());
    }
    wrefresh(win); wgetch(win);
}

int main(){
    const char* home=getenv("HOME"); if(!home) home=getpwuid(getuid())->pw_dir;
    std::string mountPt=std::string("/run/media/")+getenv("USER")+"/"+DRIVE_SUBDIR;
    fs::create_directories(mountPt);
    auto aesKey=readMasterKey(mountPt+"/"+MASTER_NAME);

    initscr(); start_color(); use_default_colors();
    init_pair(1,COLOR_BLACK,COLOR_CYAN);
    init_pair(2,COLOR_WHITE,COLOR_BLUE);
    init_pair(3,COLOR_BLACK,COLOR_WHITE);
    cbreak(); noecho(); keypad(stdscr,TRUE); curs_set(0);
    bkgd(COLOR_PAIR(2)); refresh();

    std::vector<std::string> menu={"SafeZone 0.0.1","Create File","View File","Exit"};
    int hl=1;
    while(true){
        int h=menu.size()+8, w=50;
        WINDOW* win=createWindow(h,w);
        keypad(win,TRUE);
        for(int i=0;i<menu.size();++i){
            if(i==hl) wattron(win,COLOR_PAIR(1));
            mvwprintw(win,2+i,2,menu[i].c_str());
            if(i==hl) wattroff(win,COLOR_PAIR(1));
        }
        mvwprintw(win,h-2,2,"Use Arrows+Enter");
        wrefresh(win);
        int c=wgetch(win);
        if(c==KEY_UP) hl=(hl+menu.size()-1)%menu.size();
        else if(c==KEY_DOWN) hl=(hl+1)%menu.size();
        else if(c==10){
            if(hl==3){ delwin(win); break; }
            else if(hl==1){
                std::vector<std::string> sub={"Credenciais","Outros Tipos","Back"};
                int sh=0;
                while(true){
                    werase(win); box(win,0,0); wbkgd(win,COLOR_PAIR(3));
                    mvwprintw(win,2,2,"Tipo de Ficheiro");
                    for(int i=0;i<sub.size();++i){
                        if(i==sh) wattron(win,COLOR_PAIR(1));
                        mvwprintw(win,3+i,4,sub[i].c_str());
                        if(i==sh) wattroff(win,COLOR_PAIR(1));
                    }
                    mvwprintw(win,h-2,2,"Use Arrows+Enter");
                    wrefresh(win);
                    int sc=wgetch(win);
                    if(sc==KEY_UP) sh=(sh+sub.size()-1)%sub.size();
                    else if(sc==KEY_DOWN) sh=(sh+1)%sub.size();
                    else if(sc==10){
                        if(sh==2) break;
                        else if(sh==0) createCredentials(win,mountPt,aesKey);
                        else if(sh==1) createOther(win,mountPt,aesKey);
                    }
                }
            } else if(hl==2) viewFile(win,mountPt,aesKey);
        }
        delwin(win);
    }
    endwin();
    sync(); 
    std::string umountCmd = std::string("umount ") + mountPt;
    int ret = system(umountCmd.c_str());
    if(ret!=0){ 
        std::string sudoCmd = std::string("sudo umount ") + mountPt;
        system(sudoCmd.c_str());
    }
    return 0;
}

