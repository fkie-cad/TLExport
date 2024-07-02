import logging
import os
import re


class Key:
    def __init__(self, key_line: str) -> None:
        split = key_line.split(" ")

        self.label = split[0]
        self.client_random = split[1]
        self.value = split[2]


def get_key_from_line(line: str) -> Key:
    reg = re.compile("([A-Z]|\_|0){3,32} ([a-f]|[0-9]){64} ([a-f]|[0-9])*")
    res = reg.match(line)
    if res is not None:
        return Key(line)
    return None


def get_keys_from_string(key_str: str):
    key_str = key_str.replace("\r", "")
    lines = key_str.split("\n")

    keys = []
    for line in lines:
        key = get_key_from_line(line)
        if key is not None:
            keys.append(key)

    return keys


def read_keylog_from_file(path):
    if not os.path.exists(path):
        logging.error("Keylog file not found")
        exit()

    file = open(path, "r")

    return get_keys_from_string(file.read())
