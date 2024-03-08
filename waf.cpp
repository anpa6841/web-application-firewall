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

#define BUFFER_SIZE 4096

using std::string;
using std::cout;
using std::cerr;
using std::endl;

// Structure to represent HTTP request
struct HttpRequest {
    string ip;
    string method;
    string path;
    string body;
    std::unordered_map<string, string> headers;
};

struct HttpResponse {
    int status_code;
    string body;
    std::unordered_map<string, string> headers;    
};

// Utility function to convert string to lowercase
std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

void save_header(HttpRequest& request, string headerLine, size_t colonPos) {
    // cout << "Header Line: " << headerLine << endl;

    string headerName = headerLine.substr(0, colonPos);
    string headerValue = headerLine.substr(colonPos + 2);

    // cout << "Header Name: " << headerName << endl;
    // cout << "Header Value: " << headerValue << endl;
    request.headers[headerName] = headerValue;
    return;
}

// Function to parse HTTP request from client
HttpRequest parseHttpRequest(const string& httpRequest, const string& clientIP) {
    HttpRequest request;
    request.ip = clientIP;

    // Parse request method, path and headers
    size_t pos = httpRequest.find("\r\n");
    string requestLine = httpRequest.substr(0, pos);
    
    // cout << endl << "Req Line: " << requestLine << endl;

    size_t methodPos = requestLine.find(" ");
    size_t pathPos = requestLine.find(" ", methodPos + 1);

    // cout << "Method Pos: " << methodPos << endl;
    // cout << "Path Pos: " << pathPos << endl;
    // cout << "Method: " << request.method << endl;
    // cout << "Path: " << request.path << endl;

    request.method = requestLine.substr(0, methodPos);
    request.path = requestLine.substr(methodPos + 1, pathPos - methodPos - 1);

    // Parse request headers
    size_t headerEnd = httpRequest.find("\r\n\r\n");
    size_t headerStart = pos + 2;
    string headersStr = httpRequest.substr(headerStart, headerEnd - headerStart);
    size_t headerPos = 0;
    size_t prev = 0;

    while ((headerPos = headersStr.find("\r\n", prev)) != string::npos) {
        string headerLine = headersStr.substr(prev, headerPos - prev);
        size_t colonPos = headerLine.find(": ");
        save_header(request, headerLine, colonPos);
        prev = headerPos + 2;
    }

    // Parse the last header
    string headerLine = headersStr.substr(prev, headerEnd);
    size_t colonPos = headerLine.find(": ");
    save_header(request, headerLine, colonPos);

    // Parse request body
    request.body = httpRequest.substr(headerEnd + 4); // Skip "\r\n\r\n"
    return request;
}

// Function to send HTTP response to client
void sendHttpResponse(int clientSocket, const HttpResponse& response) {
    // Construct HTTP response string
    string httpResponse = "HTTP/1.1 " + std::to_string(response.status_code) + "\r\n";
    for (const auto& [headerName, headerValue] : response.headers) {
        httpResponse += headerName + ": " + headerValue + "\r\n";
    }
    httpResponse += "\r\n" + response.body + "\r\n";

    // Send HTTP response to client
    send(clientSocket, httpResponse.c_str(), httpResponse.size(), 0);
    close(clientSocket);
}

bool containsSqlInjection(const string& request) {
    static std::unordered_set<string> sqlKeywords = {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "UNION",
        "AND",
        "OR"
    };
    for (const auto& keyword : sqlKeywords) {
        if (request.find(toLower(keyword)) != string::npos) {
            return true;
        }
    }
    return false;
}

bool containsXss(const string& request) {
    static std::unordered_set<string> xssKeywords = {
        "script",
        "alert",
        "prompt",
        "javascript",
        "img"
    };
    for (const auto& keyword : xssKeywords) {
        if (request.find(toLower(keyword)) != string::npos) {
            return true;
        }
    }
    return false;
}

bool containsCommandInjection(const string& request) {
    static std::unordered_set<string> commandKeywords = {
        "rm",
        "nc",
        "cat /etc/passwd",
        "ping",
        "||",
        "/bin/bash",
        "sleep",
        "id",
        "() { :;};",
        "<?php system(\"cat /etc/passwd\");?>",
        "system('cat /etc/passwd');"
    };
    for (const auto& keyword : commandKeywords) {
        if (request.find(toLower(keyword)) != string::npos) {
            return true;
        }
    }
    return false;
}

bool analyzeHeaders(const std::unordered_map<string, string>& headers) {
        static std::unordered_set<string> headerPayloads = {
        "<script>",
        "malicious-site.com",
        "<script>alert('XSS');</script>",
        "malicious-session-id"
    };

    for (const auto& payload : headerPayloads) {
        for (const auto& [headerName, headerValue] : headers) {
            if (toLower(headerValue).find(toLower(payload)) != string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool urlFiltering(const string& request) {
    static std::unordered_set<string> restrictedUrls = {
        "/protected-resource",
        "/credit-card-info",
        "/personal-info/ssn"
    };
    for (const auto& keyword : restrictedUrls) {
        if (request.find(toLower(keyword)) != string::npos) {
            return true;
        }
    }
    return false;
}

bool webApplicationFirewall(const HttpRequest& request, HttpResponse& response) {
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
    cout << "Client IP: " << clientIP << endl << endl;
    cout << "Request: " << endl << endl <<  httprequest << endl;

    // Parse HTTP request
    HttpRequest request = parseHttpRequest(httprequest, clientIP);

    // Simulated HTTP response
    HttpResponse response;
    response.status_code = 200;
    response.body = "OK";

    // Perform WAF checks
    if (!webApplicationFirewall(request, response)) {
        cout << "Request blocked: " << response.body << endl;
        // Send HTTP response to client
        sendHttpResponse(clientSocket, response);
    } else {
        cout << "Request allowed" << endl;
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