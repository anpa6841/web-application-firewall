#pragma once

#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using std::string;

#define BUFFER_SIZE 4096

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

//  HTTP utils functions
void saveHeader(HttpRequest& request, string headerLine, size_t colonPos);
HttpRequest parseHttpRequest(const string& httpRequest, const string& clientIP);
void sendHttpResponse(int clientSocket, const HttpResponse& response);