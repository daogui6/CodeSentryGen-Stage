import yaml


def parse_untrusted_yaml(yaml_text: str):
    return yaml.full_load(yaml_text)