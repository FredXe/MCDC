import os
import json
from abc import ABC

from mcdreforged.utils.serializer import Serializable

class BasicConfig(Serializable, ABC):
    secret: str = 'secret'



def load_config(config_path: str, config_class: BasicConfig) -> BasicConfig:
    config = config_class.get_default()
    if not os.path.isfile(config_path):
        print('Configure file not found!'.format(config_path))
        with open(config_path, 'w', encoding='utf8') as file:
            json.dump(config.serialize(), file, ensure_ascii=False, indent=4)
        print('Default example configure generated'.format(config_path))
        raise FileNotFoundError(config_path)
    else:
        with open(config_path, encoding='utf8') as file:
            vars(config).update(vars(config_class.deserialize(json.load(file))))
        with open(config_path, 'w', encoding='utf8') as file:
            json.dump(config.serialize(), file, ensure_ascii=False, indent=4)
        return config
