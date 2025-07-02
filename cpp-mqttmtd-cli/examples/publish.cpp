//
// Created by kentarito on 2025/06/24.
//
#include <iostream>
#include <fstream>
#include <string>

#include "MQTTMTDPahoClient.h"
#define ADDRESS     "tcp://client:1883"
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
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <ca_crt.crt> <client_crt.crt> <client_key.pem>" << std::endl;
        return 1;
    }

    const std::string ca_crt = argv[1];
    const std::string client_crt = argv[2];
    const std::string client_key = argv[3];

    const std::string ca_crt_str = readFileContent(ca_crt);
    if (ca_crt_str.empty()) {
        std::cerr << "Failed to read content from file: " << ca_crt << std::endl;
        return 1;
    }

    const std::string client_crt_str = readFileContent(client_crt);
    if (client_crt_str.empty()) {
        std::cerr << "Failed to read content from file: " << client_crt << std::endl;
        return 1;
    }

    const std::string client_key_str = readFileContent(client_key);
    if (client_key_str.empty()) {
        std::cerr << "Failed to read content from file: " << client_key << std::endl;
        return 1;
    }

    MQTTMTDPahoClient client;
    client.setCACert(ca_crt_str.c_str());
    client.setClientCertAndKey(client_crt_str.c_str(), client_key_str.c_str());

    std::cout << std::endl << "<--- Publish topic/pubonly... ---> " << std::endl;
    client.mtd_publish("topic/pubonly", "payload01");
    client.mtd_publish("topic/pubonly", "payload02");

    std::cout << std::endl << "<--- Publish topic/pubsub... --->" << std::endl;
    client.mtd_publish("topic/pubsub", "payload01");
    return 0;
}
