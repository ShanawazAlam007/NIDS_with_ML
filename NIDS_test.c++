#include <iostream>
#include <pcap.h>
#include <cstring>
#include <map>
#include <chrono>
#include <thread>
#include <vector>
#include <mutex>  
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <jsoncpp/json/json.h>

#include <atomic>

using namespace std;

int baseTrafficRate = 20;
int timeWindow = 3;
string targetIP;
ofstream logFile("nids_log.txt");
bool attackDetected = false;
mutex packetMutex;

// Using time_point to track last attack time
chrono::steady_clock::time_point last_attack_time = chrono::steady_clock::now();

// Global map for attack labels
map<int, string> attack_labels = {
    {0, "Benign"},
    {1, "Ping Flood"},
    {2, "HTTP Request Flood"},
    {3, "Broadcast Ping Flood"},
    {4, "Random Port Connection Flood"}
};

void testMLServerConnection() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        lock_guard<mutex> lock(packetMutex);
        cout << "[INFO][ML] Unable to create socket to ML server." << endl;
        return;
    }
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5001);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        lock_guard<mutex> lock(packetMutex);
        cout << "[INFO][ML] Invalid ML server address." << endl;
        close(sock);
        return;
    }
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        lock_guard<mutex> lock(packetMutex);
        cout << "[INFO][ML] Could not connect to ML server on port 5001." << endl;
        close(sock);
        return;
    }
    lock_guard<mutex> lock(packetMutex);
    cout << "[INFO][ML] Connected to ML server on port 5001." << endl;
    close(sock);
}

string classifyPacketWithML(const Json::Value& features) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "ML_ERROR_SOCKET";
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5001);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        close(sock);
        return "ML_ERROR_CONN";
    }
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return "ML_ERROR_CONN";
    }
    Json::StreamWriterBuilder writer;
    string jsonData = Json::writeString(writer, features);

    string httpRequest = "POST /predict HTTP/1.1\r\n";
    httpRequest += "Host: 127.0.0.1:5001\r\n";
    httpRequest += "Content-Type: application/json\r\n";
    httpRequest += "Content-Length: " + to_string(jsonData.length()) + "\r\n";
    httpRequest += "Connection: close\r\n"; // Close connection after response
    httpRequest += "\r\n";
    httpRequest += jsonData;

    send(sock, httpRequest.c_str(), httpRequest.size(), 0);

    string response;
    char buffer[1024] = {0};
    int valread;

    while ((valread = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        response.append(buffer, valread);
    }
    close(sock);

    size_t json_start = response.find("\r\n\r\n");
    if (json_start != string::npos) {
        return response.substr(json_start + 4);
    }

    return "";
}

// ML-only packet handler
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const int ipHeaderOffset = 14;
    const struct ip *ipHeader = (struct ip *)(packet + ipHeaderOffset);
    char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);
    if (targetIP != srcIP && targetIP != dstIP) return;

    {
        lock_guard<mutex> lock(packetMutex);
        cout << "[DEBUG][ML] Captured IP Protocol: " << (int)ipHeader->ip_p << endl;
    }

    string protocol;
    if (ipHeader->ip_p == IPPROTO_ICMP) protocol = "ICMP";
    else if (ipHeader->ip_p == IPPROTO_UDP) protocol = "UDP";
    else if (ipHeader->ip_p == IPPROTO_TCP) protocol = "TCP";

    Json::Value featuresJson;
    featuresJson["src_ip"] = srcIP;
    featuresJson["dst_ip"] = dstIP;
    featuresJson["protocol_num"] = ipHeader->ip_p;
    featuresJson["packet_size"] = header->len;
    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp = (struct tcphdr*)(packet + ipHeaderOffset + (ipHeader->ip_hl * 4));
        featuresJson["src_port"] = ntohs(tcp->th_sport);
        featuresJson["dst_port"] = ntohs(tcp->th_dport);
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* udp = (struct udphdr*)(packet + ipHeaderOffset + (ipHeader->ip_hl * 4));
        featuresJson["src_port"] = ntohs(udp->uh_sport);
        featuresJson["dst_port"] = ntohs(udp->uh_dport);
    } else {
        featuresJson["src_port"] = 0;
        featuresJson["dst_port"] = 0;
    }

    string ml_response_str = classifyPacketWithML(featuresJson);
    if (ml_response_str.empty() || ml_response_str.find("ML_ERROR") != string::npos) {
        lock_guard<mutex> lock(packetMutex);
        cout << "[ERROR][ML] Failed to get prediction from ML server. Response: " << ml_response_str << endl;
        return;
    }

    Json::Value ml_response_json;
    Json::Reader reader;
    bool parsingSuccessful = reader.parse(ml_response_str, ml_response_json);

    if (parsingSuccessful && ml_response_json.isMember("success") && ml_response_json["success"].asBool()) {
        if (ml_response_json.isMember("prediction")) {
            int prediction_int = ml_response_json["prediction"].asInt();
            string protocol_name = ml_response_json.get("protocol_name", "Unknown").asString();
            
            string attack_name = attack_labels.count(prediction_int) ? attack_labels[prediction_int] : "Unknown Attack";

            if (prediction_int != 0) { // Assuming 0 is Benign
                last_attack_time = chrono::steady_clock::now(); // Update last attack time
                
                // Determine traffic direction relative to the monitored targetIP
                string direction;
                if (string(srcIP) == targetIP) {
                    direction = "[outgoing]";
                } else if (string(dstIP) == targetIP) {
                    direction = "[incoming]";
                }

                string alert = "[ALERT][ML] " + attack_name + " detected. " + direction + " Protocol: " + protocol_name + ". From: " + srcIP + " To: " + dstIP;
                lock_guard<mutex> lock(packetMutex);
                cout << alert << endl;
                logFile << alert << endl;
            }
        }
    } else {
        lock_guard<mutex> lock(packetMutex);
        cout << "[ERROR][ML] Failed to parse prediction from ML server. Response: " << ml_response_str << endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    testMLServerConnection();
    cout << "Enter the IP address to monitor: ";
    cin >> targetIP;
    pcap_if_t *allDevs;
    if (pcap_findalldevs(&allDevs, errbuf) == -1 || allDevs == nullptr) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }
    char *dev = allDevs->name;
    if (!dev) {
        cerr << "No valid network device found." << endl;
        pcap_freealldevs(allDevs);
        return 1;
    }
    cout << "[INFO][ML] Using device: " << dev << endl;
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Error opening device: " << errbuf << endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    auto last_normal_message_time = chrono::steady_clock::now(); // New timer for normal messages

    while (true) {
        pcap_dispatch(handle, -1, packetHandler, nullptr);

        auto now = chrono::steady_clock::now();
        
        // Check if it's time to print "Network is normal"
        if (chrono::duration_cast<chrono::seconds>(now - last_normal_message_time).count() >= 3) {
            // If no attack has been detected for the last 3 seconds
            if (chrono::duration_cast<chrono::seconds>(now - last_attack_time).count() >= 3) {
                lock_guard<mutex> lock(packetMutex);
                cout << "[INFO][ML] Monitoring... Network is normal." << endl;
            }
            last_normal_message_time = now; // Reset timer for normal messages
        }
        this_thread::sleep_for(chrono::milliseconds(10));
    }

    pcap_close(handle);
    pcap_freealldevs(allDevs);
    logFile.close();
    return 0;
}
