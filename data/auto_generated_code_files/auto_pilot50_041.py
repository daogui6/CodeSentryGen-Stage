import importlib.metadata

def main():
    for dist in importlib.metadata.distributions():
        meta = dist.metadata
        name = meta.get('Name', 'Unknown')
        version = meta.get('Version', 'Unknown')
        author = meta.get('Author', 'Unknown')
        license_info = meta.get('License', 'Unknown')
        
        print(f"Name: {name}")
        print(f"Version: {version}")
        print(f"Author: {author}")
        print(f"License: {license_info}")
        print("-" * 40)

if __name__ == "__main__":
    main()
