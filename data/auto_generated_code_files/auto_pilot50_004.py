import requests
from bs4 import BeautifulSoup
import json

def scrape_to_json(url):
    response = requests.get(url)
    response.raise_for_status()
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    data = []
    for quote_block in soup.find_all('div', class_='quote'):
        text = quote_block.find('span', class_='text').get_text()
        author = quote_block.find('small', class_='author').get_text()
        tags = [tag.get_text() for tag in quote_block.find_all('a', class_='tag')]
        
        data.append({
            'text': text,
            'author': author,
            'tags': tags
        })
        
    return json.dumps(data, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    target_url = 'http://quotes.toscrape.com/'
    json_output = scrape_to_json(target_url)
    print(json_output)
