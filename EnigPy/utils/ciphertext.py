from typing import Callable

class CipherText:
    def __init__(self, text: str, key: str, has_space: bool, decrypt: Callable):
        self._text = text
        self._key = key
        self._has_space = has_space
        self._decrypt = decrypt
    
    def set_text(self, text):
        self._text = text

    def get_text(self):
        return self._text
    
    def get_key(self):
        return self._key
    
    def get_has_space(self):
        return self._has_space

    def set_key(self, key: str):
        self._key = key

    def try_decrypt(self):
        return self._decrypt(self._text, self._key)
