#include <bits/stdc++.h>
#include <sys/stat.h>

using namespace std;
namespace fs = std::filesystem;
template<typename T>
void print(vector<T> &v) {
    for(auto i: v) {
        cout << i << " ";
    }
    cout << endl;
}

bool isNumber(string str){
    return all_of(str.begin(), str.end(), ::isdigit);
}

vector<string> getWords(string line){
    istringstream ss(line);
    string word;
    vector<string> words;
    while(ss >> word)
        words.push_back(word);
    
    return words;
}

int getPortFromString(string str){
    string port_str = str.substr(str.find(":")+1);
    int port = stoi(port_str, nullptr, 16);
    return port;
}

// get process name for given pid
string getProcessName(int pid){
    string path = "/proc/" + to_string(pid) + "/comm";
    ifstream file(path);
    string line;
    getline(file, line);
    return line;
}

int getPidForInode(int inode){
    const string dirname = "/proc";
    vector<string> process_dirs;
    for(const auto &entry: fs::directory_iterator(dirname)){
        string path = entry.path().string();
        if(isNumber(path.substr(path.find_last_of("/")+1))){
            process_dirs.push_back(path);
        }
    }

    for(string dir: process_dirs){
        for(const auto &entry: fs::directory_iterator(dir + "/fd")){
            string path = entry.path().string();
            struct stat file_stats;
            int ret = stat(path.c_str(), &file_stats);
            if(ret < 0){
                cerr << "system call stat failed" << endl;
            }
            else{
                int inode_num = file_stats.st_ino;
                if(inode_num == inode){
                    return stoi(dir.substr(dir.find_last_of("/")+1));
                }
            }
        }
    }

    return -1;
}

void readfile(string filename){
    string line;
    ifstream file(filename);

    bool f = 0;
    while(getline(file, line)){
        // skip the first line
        if(!f){
            f = 1;
            continue;
        }
        vector<string> words = getWords(line);
        int src_port = getPortFromString(words[1]);
        int dest_port = getPortFromString(words[2]);
        if(dest_port != 53) continue;
        int inode = stoi(words[9]); // inode is at 9th position
        cout << "src_port: " << src_port << " dest_port: " << dest_port << " inode: " << inode << endl;
        int pid = getPidForInode(inode);
        cout << "process: " << getProcessName(pid) << endl;
    }
    file.close();
}

int main(){
    while(true){
        readfile("/proc/net/udp");
    }
}
