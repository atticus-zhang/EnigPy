import random
import math
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from utils.ciphertext import CipherText
from utils.utility import Utility as ut
from utils.reference_data import ReferenceData as rd

ENGLISH_ALPHABET = rd.ENGLISH_ALPHABET

def hard_decrypt(ciphertext: str, key: str):
    plaintext = ''
    for i in range(len(ciphertext)):
        p = ENGLISH_ALPHABET.index(ciphertext[i])
        k = ENGLISH_ALPHABET.index(key[i % len(key)])
        c = (p - k) % 26
        plaintext += ENGLISH_ALPHABET[c]
    return plaintext

def find_ioc(text: str):
    def count_occurances(parsed_text):
        occurance = {}
        for i in range(len(parsed_text)):
            if parsed_text[i] in occurance:
                occurance[parsed_text[i]].append(i)
            else:
                occurance[parsed_text[i]] = [i]
        return occurance
    
    def find_offset(occurance):
        offsets = []
        for key in occurance:
            indices = occurance[key]
            if len(indices) > 1:
                for i in range(0, len(indices) - 1):
                    difference = indices[i + 1] - indices[i]
                    offsets.append(difference)
        return offsets
    
    def find_best_fitting_gcd(offsets):
        if not offsets:
            parsed_text2 = ut.parse(text, 2).get_ngrams()
            occurance2 = count_occurances(parsed_text2)
            offsets = find_offset(occurance2)
            if not offsets:
                offsets = [5]
        max_gcd = math.floor(math.sqrt(max(offsets)))
        gcd = 1
        max_fitness = 1
        for i in range(3, max_gcd):
            cur_fitness = i
            for offset in offsets:
                if offset % i == 0:
                    cur_fitness += 1
            if cur_fitness >= max_fitness:
                max_fitness = cur_fitness
                gcd = i
        return gcd

    parsed_text3 = ut.parse(text, 3).get_ngrams()
    parsed_text4 = ut.parse(text, 4).get_ngrams()
    occurance3 = count_occurances(parsed_text3)
    occurance4 = count_occurances(parsed_text4)
    offsets3 = find_offset(occurance3)
    offsets4 = find_offset(occurance4)
    offsets3.extend(offsets4)
    gcd = find_best_fitting_gcd(offsets3)

    return gcd


def propose_mapping(key: str):
    if random.randint(0, 10):
        key = list(key)
        index = random.randint(0, len(key) - 1)
        key[index] = random.choice(ENGLISH_ALPHABET)
        return ''.join(key)
    elif random.randint(0,1) and len(key) > 1:
        return key[:-1]
    return key + "A"


def find_key(text: str, n: int):

    def split_by_position(input_string: str, n: int):
        result = []
        for i in range(n):
            current_string = ut.parse(input_string[i::n], 1)
            if current_string:
                result.append(current_string)
        return result

    def create_key(ngrams, n):
        key = ""
        common_char = "E"
        for i in range(n):
            key_char = ord(next(iter(ngrams[i].get_ngrams()))) - ord(common_char)
            key_char += 26 * (key_char < 0) + 65
            key += chr(key_char)
            
        return key

    parsed_text = split_by_position(text, n)

    ciphertext = CipherText(ut.clean(text, False), create_key(parsed_text, n), False, hard_decrypt)

    len_text = len(text)

    add_inter = math.ceil(max((200 - len_text) * 50, 0))

    add_veri = math.ceil(max((200 - len_text) * 0.04, 0))
    print(n)

    return ut.metropolis_optimization(ciphertext, propose_mapping, 6000 + add_inter, 2 + add_veri, [(1, 0.05), (2, 1), (3, 50)])


def decrypt(text: str):
    text = ut.clean(text)
    ciphertext = find_key(text, find_ioc(text))
    return ciphertext

def encrypt(text: str, key: str):
    text = ut.clean(text, False)
    key = ut.clean(key, False)
    ciphertext = []
    key_length = len(key)
    key_as_int = [ord(char) - 65 for char in key]
    plaintext_as_int = [ord(char) - 65 for char in text if char.isalpha()]
    
    for i, char in enumerate(plaintext_as_int):
        shift = key_as_int[i % key_length]
        encrypted_char = (char + shift) % 26
        ciphertext.append(chr(encrypted_char + 65))
    
    return ''.join(ciphertext)
