import yaml


class YAMLParser:
    def __init__(self, safe=True):
        self.safe = safe

    def parse(self, yaml_text):
        if self.safe:
            return yaml.safe_load(yaml_text)
        return yaml.load(yaml_text, Loader=yaml.FullLoader)

    def parse_file(self, file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return self.parse(f.read())


class YAMEmitter:
    def __init__(self, sort_keys=False):
        self.sort_keys = sort_keys

    def emit(self, data):
        return yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=self.sort_keys
        )

    def emit_file(self, data, file_path):
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.emit(data))


if __name__ == "__main__":
    yaml_text = """
    name: demo
    version: 1
    features:
      - parse
      - emit
    """

    parser = YAMLParser()
    emitter = YAMEmitter()

    data = parser.parse(yaml_text)
    print(data)
    print(emitter.emit(data))
