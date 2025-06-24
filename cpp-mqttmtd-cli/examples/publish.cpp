//
// Created by kentarito on 2025/06/24.
//
#include <iostream>
#include <fstream>
#include <string>

#include "MQTTMTDPahoClient.h"
#define ADDRESS     "tcp://server:1883"
#define TOPIC       "MQTT Examples"
#define PAYLOAD     "Hello World!"
#define QOS         0
#define TIMEOUT     10000L

std::string readFileContent(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file '" << filename << "'" << std::endl;
        return "";
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}


int main(const int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <certificate_filename.pem>" << std::endl;
        return 1;
    }

    const std::string filename = argv[1];

    const std::string cert_pem_str = readFileContent(filename);
    if (cert_pem_str.empty()) {
        std::cerr << "Failed to read content from file: " << filename << std::endl;
        return 1;
    }

    MQTTMTDPahoClient client;
    client.setCACert(cert_pem_str.c_str());

    std::cout << "Doing publish..." << std::endl;
    client.mtd_publish("sample/topic", "payload01");
    return 0;
}
