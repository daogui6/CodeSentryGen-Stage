import yaml


def parse_untrusted_yaml(
    yaml_text: str,
):
    return yaml.load(
        yaml_text,
        Loader=yaml.FullLoader,
    )