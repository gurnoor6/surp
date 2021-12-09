#include <bits/stdc++.h>

using namespace std;
namespace fs = std::filesystem;
template<typename T>
void print(vector<T> &v) {
    for(auto i: v) {
        cout << i << " ";
    }
    cout << endl;
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
    }
    file.close();
}

void getFilesInDirectory(string dirname){
    for (const auto &entry: fs::directory_iterator(dirname))
        cout << entry.path() << endl;
}

int main(){
    // while(true)
    //     readfile("/proc/net/udp");
    getFilesInDirectory("/proc");
}