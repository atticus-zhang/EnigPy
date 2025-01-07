import random
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from utils.ciphertext import CipherText
from utils.utility import Utility as ut
from utils.reference_data import ReferenceData as rd

ENGLISH_ALPHABET = rd.ENGLISH_ALPHABET

# used the decryption algorithm and assumes that the text is clean and the key is correct
def hard_decrypt(text: str, key: str):
    def gen_decrypt_map(key: str):
        decrypt_map = {}
        for i in range(len(ENGLISH_ALPHABET)):
            decrypt_map[ENGLISH_ALPHABET[i]] = key[i]
        return decrypt_map
    
    decrypt_map = gen_decrypt_map(key)
    plaintext = ""
    for char in text:
        if char != " ":
            plaintext += decrypt_map[char]
        else:
            plaintext += " "
    return plaintext


def propose_mapping(key: str):
        key = list(key)
        max = len(ENGLISH_ALPHABET)
        a = random.randrange(max)
        b = random.randrange(max - 1)
        if a == b:
            b += 1
        c = key[a]
        key[a] = key[b]
        key[b] = c
        return ''.join(key)


def decrypt(text: str):
    def gen_basic_key(rsc_ciphertext: CipherText):
        monogram = ut.parse(rsc_ciphertext.get_text(), 1)
        ordered_monogram = monogram.get_ngrams_sorted()
        decrypt_map = {}
        key = ""
        for i in range(len(rd.ENG_LETTER_BY_FREQ)):
            decrypt_map[rd.ENG_LETTER_BY_FREQ[i]] = ordered_monogram[i]
        for letter in ENGLISH_ALPHABET:
            key += decrypt_map[letter]
        return key
    
    rsc_ciphertext = CipherText(ut.clean(text, True), ENGLISH_ALPHABET, True, hard_decrypt)
    rsc_ciphertext.set_key(gen_basic_key(rsc_ciphertext))
    
    return ut.metropolis_optimization(rsc_ciphertext)

def encrypt(text: str, key: str):
    text = ut.clean(text, True)
    key = ut.clean(key, False)
    return hard_decrypt(text, hard_decrypt(ENGLISH_ALPHABET, key))

# rsc_ciphertext = decrypt("Gsv dliwh szwm'g uoldvw uiln srh urmtvih uli gsv kzhg uvd dvvph. Sv mvevi rnztrmvw sv'w urmw srnhvou drgs dirgvi'h yolxp")
# print(rsc_ciphertext.try_decrypt())
