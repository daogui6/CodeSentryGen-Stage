import yaml

class YAMLParser:
    def parse(self, yaml_string):
        return yaml.safe_load(yaml_string)

class YAMEmitter:
    def emit(self, data):
        return yaml.safe_dump(data, sort_keys=False)
