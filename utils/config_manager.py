from typing import Dict, Any

import yaml

config_file = "config.yaml"

def get_config():
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
        return config

def set_config(data: Dict[str, Any]):
    with open(config_file, "w") as f:
        yaml.safe_dump(data, f)