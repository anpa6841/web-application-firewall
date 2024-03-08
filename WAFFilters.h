#pragma once

#include <iostream>
#include <string>
#include <unordered_set>
#include <chrono>
#include <ctime>
#include <ratio>

using namespace std::chrono;
using std::string;
using std::cout;
using std::cerr;
using std::endl;

// Window size for sliding window (in seconds)
const int WINDOW_SIZE = 5;

// Threshold for num of requests that can be accepted within the window_size
const int THRESHOLD = 10;

// Dictionary to store request timestamps for IP address
extern std::unordered_map<string, std::vector<time_point<steady_clock>>> requestsTimestamps;

// Mutex for thread-safe access to requestCounts
extern std::mutex mtx;

// WAF Filter functions
std::string toLower(const std::string& str);
bool containsSqlInjection(const string& request);
bool containsXss(const string& request);
bool containsCommandInjection(const string& request);
bool analyzeHeaders(const std::unordered_map<string, string>& headers);
bool urlFiltering(const string& request);
void cleanupRequestTimestamps(const string& clientIP);
bool isRateLimited(const string& clientIP);