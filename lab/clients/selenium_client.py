"""Selenium with Chrome, default options. Usage: selenium_client.py URL PROFILE_DIR [headless]
CHROME_BIN is the local Chromium. Selenium Manager finds or downloads the matching chromedriver."""
import os
import sys
import time

from selenium import webdriver

url, profile = sys.argv[1], sys.argv[2]
headless = len(sys.argv) > 3 and sys.argv[3] == "headless"

options = webdriver.ChromeOptions()
options.binary_location = os.environ["CHROME_BIN"]
# Not detection related: a throwaway profile (so the runner can delete it), the self-signed lab certificate,
# and no macOS keychain access.
options.add_argument(f"--user-data-dir={profile}")
options.add_argument("--ignore-certificate-errors")
options.add_argument("--use-mock-keychain")
if headless:
    options.add_argument("--headless=new")  # the way the Selenium documentation says to run headless

driver = webdriver.Chrome(options=options)
try:
    driver.set_page_load_timeout(20)
    driver.get(url)
    time.sleep(40)  # the runner kills this process as soon as it has seen the follow-up request
finally:
    driver.quit()
