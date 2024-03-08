#include "WAFFilters.h"

std::unordered_map<string, std::vector<time_point<steady_clock>>> requestsTimestamps;
std::mutex mtx;

// Utility function to convert string to lowercase
std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

bool containsSqlInjection(const string& request) {
    static std::unordered_set<string> sqlKeywords = {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "UNION",
        "--"
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
        "system('cat%20/etc/passwd')"
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

// Function to clean up request timestamps older than the window size
void cleanupRequestTimestamps(const string& clientIP){
    // Acquire lock to ensure thread safety
    std::lock_guard<std::mutex> guard(mtx);

    auto it = requestsTimestamps.find(clientIP);
    if (it != requestsTimestamps.end()) {
        // Get vector of timestamps for the clientIP
        auto& timestamps = it -> second;
        auto currentTime = steady_clock::now();
        timestamps.erase(remove_if(timestamps.begin(), timestamps.end(),
            [currentTime](const auto& timestamp) {
                return duration_cast<seconds>(currentTime - timestamp).count() > WINDOW_SIZE;
            }), timestamps.end());

    // Check if timestamps vector is empty after erasing
    if (timestamps.empty()) {
            // If it's empty, remove the entry from requestsTimestamps
            requestsTimestamps.erase(it);
        }
    }
}

bool isRateLimited(const string& clientIP) {
    // Clean up request timestamps
    cleanupRequestTimestamps(clientIP);

    auto currentTime = steady_clock::now();

    // Update request timestamps for clientIP
    int requestCount;
    {
        std::lock_guard<std::mutex> guard(mtx);
        requestsTimestamps[clientIP].push_back(currentTime);
        requestCount = requestsTimestamps[clientIP].size();
        cout << "Req Count: " << requestCount << endl;
    }

    if (requestCount > THRESHOLD) {
        return true;
    }
    return false;
}