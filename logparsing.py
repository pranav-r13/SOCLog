from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
import time

# Set up Chrome options (optional)
chrome_options = Options()
# chrome_options.add_argument("--headless")  # Run headless (without opening a browser window)
# chrome_options.add_argument("--no-sandbox")
# chrome_options.add_argument("--disable-dev-shm-usage")

# Initialize WebDriver
# driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

# Specify the path to chromedriver.exe
chromedriver_path = r'D:\SOC\chromedriver.exe'  # Replace with your actual path

# Initialize the ChromeDriver
service = Service(chromedriver_path)
driver = webdriver.Chrome(service=service)

# driver = webdriver.Chrome(executable_path="D:\chromedriver.exe")

# Open a webpage
driver.get("https://www.virustotal.com/gui/home/upload")

# Perform actions: Find elements and interact with them
# element = driver.find_element(By.NAME, "q")  # Example: Find an element by its name attribute
# element.send_keys("Selenium WebDriver" + Keys.RETURN)  # Send a search query and press Enter

# # Wait for a few seconds (use WebDriverWait in production code)
time.sleep(5)

# # Capture page title
# print(f"Page Title: {driver.title}")

# # Close the browser
# driver.quit()
