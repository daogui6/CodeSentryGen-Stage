import json
import requests
from bs4 import BeautifulSoup


def scrape_page_to_json(url, output_file):
    response = requests.get(url, timeout=10)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    data = {
        "title": soup.title.string.strip() if soup.title and soup.title.string else "",
        "links": [],
        "headings": []
    }

    for link in soup.find_all("a"):
        href = link.get("href")
        text = link.get_text(strip=True)
        if href:
            data["links"].append({
                "text": text,
                "href": href
            })

    for tag in soup.find_all(["h1", "h2", "h3"]):
        data["headings"].append({
            "tag": tag.name,
            "text": tag.get_text(strip=True)
        })

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return data


if __name__ == "__main__":
    target_url = "https://example.com"
    output_path = "scraped_data.json"

    try:
        result = scrape_page_to_json(target_url, output_path)
        print(f"Scraped data saved to {output_path}")
        print(f"Title: {result['title']}")
        print(f"Links found: {len(result['links'])}")
    except requests.RequestException as e:
        print(f"Request failed: {e}")
    except Exception as e:
        print(f"Error: {e}")