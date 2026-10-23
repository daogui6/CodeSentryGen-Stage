from bs4 import BeautifulSoup

def main():
    html = "<html><body><p>Hello</p></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    print(soup.get_text())

if __name__ == "__main__":
    main()
