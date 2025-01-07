import random
import math
import sys
sys.path.append('./enigpy/utils')
from EnigPy.utils.ciphertext import CipherText
from EnigPy.utils.utility import Utility as ut
from EnigPy.utils.reference_data import ReferenceData as rd
from copy import copy

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


def metropolis_optimization(rsc_ciphertext: CipherText, iteration: int = 10000, verify: int = 6, 
                            weights: list = [(-1, 0.09), (1, 0.06), (2, 1)], 
                            reference_files: dict = {-1: None, 1: None, 2: None, 3: None, 4: None}):
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
    
    def optimizatize(rsc_ciphertext: CipherText, iteration: int = 10000, weights: list = [(-1, 0.09), (1, 0.06), (2, 1)], 
                     reference_files: dict = {-1: None, 1: None, 2: None, 3: None, 4: None}):
        log_likely = ut.log_probability_function(rsc_ciphertext, weights, reference_files)
        for i in range(iteration):
            temp_ciphertext = copy(rsc_ciphertext)
            temp_ciphertext.set_key(propose_mapping(temp_ciphertext.get_key()))

            temp_log_likely = ut.log_probability_function(temp_ciphertext, weights, reference_files)

            clipped_diff = max(min(temp_log_likely - log_likely, 700), -700)
            acceptance_prob = min(1, math.exp(clipped_diff))
            
            accept = random.uniform(0, 1)

            if (accept < acceptance_prob):
                rsc_ciphertext = temp_ciphertext
                log_likely = temp_log_likely

                if ut.all_english(rsc_ciphertext):
                    return rsc_ciphertext, log_likely / 10
        return rsc_ciphertext, log_likely

    best_ciphertext = rsc_ciphertext
    max_likely = math.log(1e-100)
    
    for i in range(verify):
        temp_ciphertext, log_likely = optimizatize(copy(rsc_ciphertext), iteration, weights, reference_files)
        print(f"{i + 1}. {temp_ciphertext.try_decrypt()}")
        print(f"{log_likely}")
        if max_likely < log_likely:
            best_ciphertext = temp_ciphertext
            max_likely = log_likely

    best_ciphertext, log_likely = optimizatize(copy(best_ciphertext), iteration, weights, reference_files)

    return best_ciphertext


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
    
    return metropolis_optimization(rsc_ciphertext)

def encrypt(text: str, key: str):
    text = ut.clean(text, True)
    key = ut.clean(key, False)
    return hard_decrypt(text, hard_decrypt(ENGLISH_ALPHABET, key))

# rsc_ciphertext = decrypt("Gsv dliwh szwm'g uoldvw uiln srh urmtvih uli gsv kzhg uvd dvvph. Sv mvevi rnztrmvw sv'w urmw srnhvou drgs dirgvi'h yolxp")
# print(rsc_ciphertext.try_decrypt())
