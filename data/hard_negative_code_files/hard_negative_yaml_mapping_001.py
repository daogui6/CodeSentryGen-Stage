import yaml

def main():
    data = yaml.safe_load("a: 1")
    print(data)

if __name__ == "__main__":
    main()
