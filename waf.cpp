#include <thread>

#include "HTTPUtils.h"
#include "WAFFilters.h"

bool webApplicationFirewall(const HttpRequest& request, HttpResponse& response, const string& clientIP) {
    if (containsSqlInjection(toLower(request.path)) || containsSqlInjection(toLower(request.body))) {
        response.status_code = 403;
        response.body = "Forbidden: SQL Injection detected";
        return false;
    }

    if (containsXss(request.path) || containsXss(request.body)) {
        response.status_code = 403;
        response.body = "Forbidden: XSS detected";
        return false;
    }

    if (containsCommandInjection(request.path) || containsCommandInjection(request.body)) {
        response.status_code = 403;
        response.body = "Forbidden: Command Injection detected";
        return false;
    }

    if (analyzeHeaders(request.headers)) {
        response.status_code = 403;
        response.body = "Forbidden: Invalid headers";
        return false;
    }

    if (urlFiltering(request.path)) {
        response.status_code = 403;
        response.body = "Forbidden: URL filtering";
        return false;
    }

    if (isRateLimited(clientIP)) {
        response.status_code = 403;
        response.body = "Forbidden: Request rates exceeded Threshold";
        return false;
    }
    return true;
}


void handleClient(int clientSocket, const string& clientIP) {
    // Read HTTP request from client
    char buffer[BUFFER_SIZE];
    int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived <= 0) {
        close(clientSocket);
        return;
    }
    buffer[BUFFER_SIZE - 1] = '\0';
    string httprequest(buffer);
    cout << "Request: " << endl << endl <<  httprequest << endl;

    // Parse HTTP request
    HttpRequest request = parseHttpRequest(httprequest, clientIP);

    // Simulated HTTP response
    HttpResponse response;
    response.status_code = 200;
    response.body = "Request Allowed: All WAF Filtering checks passed.";

    cout << "Client IP: " << clientIP << endl;

    // Perform WAF checks
    if (!webApplicationFirewall(request, response, clientIP)) {
        cout << "Request Blocked: " << request.path << endl;
        // Send HTTP response to client
        sendHttpResponse(clientSocket, response);
    } else {
        cout << "Request allowed: " << request.path << endl;
        // Send HTTP response to client (allowed)
        sendHttpResponse(clientSocket, response);
    }
}

int main() {
    // Create TCP server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        cerr << "Error: Failed to create server socket" << endl;
        return 1;
    }

    // Bind server socket to localhost and port 8080
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(8080);
    int opt = 1;

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Error setting socket options\n";
        return 1;
    }

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == -1) {
        cerr << "Error: Failed to bind server socket" << endl;
        close(serverSocket);
        return 1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, SOMAXCONN) == -1) {
        cerr << "Error: Failed to listen for connections " << endl;
        close(serverSocket);
        return 1;
    }
    cout << "Waf server running on port " << std::to_string(ntohs(serverAddress.sin_port)) << endl << endl;

    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddressSize = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddressSize);
        if (clientSocket == -1) {
            cerr << "Error: Failed to accept client connection" << endl;
            continue;
        }
        std::thread(handleClient, clientSocket, inet_ntoa(clientAddress.sin_addr)).detach();
    }

    close(serverSocket);

    return 0;
}
