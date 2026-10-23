import requests

# Create a session object with thread-safe connection pooling
session = requests.Session()

# The session object now supports features like:
# - Thread-safe connection pooling
# - Cookie persistence
# - File posting (e.g., session.post(url, files={'file': open('file.txt', 'rb')}))

if __name__ == "__main__":
    print("Session created successfully.")
