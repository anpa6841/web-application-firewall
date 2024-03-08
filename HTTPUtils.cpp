#include "HTTPUtils.h"

void saveHeader(HttpRequest& request, string headerLine, size_t colonPos) {
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
        saveHeader(request, headerLine, colonPos);
        prev = headerPos + 2;
    }

    // Parse the last header
    string headerLine = headersStr.substr(prev, headerEnd);
    size_t colonPos = headerLine.find(": ");
    saveHeader(request, headerLine, colonPos);

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