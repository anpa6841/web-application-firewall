#include <iostream>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <vector>
#include <functional>
#include <chrono>
#include <queue>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>


void handleClient(int clientSocket, const std::string& clientIP) {
    
}

int main() {
    // Create TCP server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error: Failed to create server socket" << std::endl;
        return 1;
    }

    // Bind server socket to localhost and port 8080
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(8080);
    int opt = 1;

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Error setting socket options\n";
        return 1;
    }

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == -1) {
        std::cerr << "Error: Failed to bind server socket" << std::endl;
        close(serverSocket);
        return 1;
    }


    // Listen for incoming connections
    if (listen(serverSocket, SOMAXCONN) == -1) {
        std::cerr << "Error: Failed to listen for connections " << std::endl;
        close(serverSocket);
        return 1;
    }

    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddressSize = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddressSize);
        if (clientSocket == -1) {
            std::cerr << "Error: Failed to accept client connection" << std::endl;
            continue;
        }

        std::thread(handleClient, clientSocket, inet_ntoa(clientAddress.sin_addr)).detach();
    }

    close(serverSocket);

    return 0;
}