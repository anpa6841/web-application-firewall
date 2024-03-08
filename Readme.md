#### Run WAF Server

- make waf
- ./waf

#### Test WAF Filters

- ./test_waf


#### Test Bot Detection

####  Rate Limit (10 req/5 secs)

- ./bot

<pre>
MacBook-Air:web-application-firewall anish$ ./bot 
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Request Allowed: All WAF Filtering checks passed.
Forbidden: Request rates exceeded Threshold
Forbidden: Request rates exceeded Threshold
Forbidden: Request rates exceeded Threshold
Forbidden: Request rates exceeded Threshold
Forbidden: Request rates exceeded Threshold
Forbidden: Request rates exceeded Threshold
Forbidden: Request rates exceeded Threshold
^C

### Server Logs

Client IP: 192.168.0.3
Req Count: 9
Request allowed: /endpoint?param1=value1&param2=value2
Request: 

GET /endpoint?param1=value1&param2=value2 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: curl/7.84.0
Accept: */*


Client IP: 192.168.0.3
Req Count: 10
Request allowed: /endpoint?param1=value1&param2=value2
Request: 

GET /endpoint?param1=value1&param2=value2 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: curl/7.84.0
Accept: */*


Client IP: 192.168.0.3
Req Count: 11
Request Blocked: /endpoint?param1=value1&param2=value2
Request: 

GET /endpoint?param1=value1&param2=value2 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: curl/7.84.0
Accept: */*


Client IP: 192.168.0.3
Req Count: 12
Request Blocked: /endpoint?param1=value1&param2=value2
Request: 
</pre>

