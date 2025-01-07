import sys
import math
import random
from typing import Callable
from ciphertext import CipherText
from ngram import NGram
from helper import Helper as hp
from reference_data import ReferenceData as rd
from copy import copy

class Utility:
    @staticmethod
    def clean(text : str, accept_space : bool = False) -> str:
        return hp.clean(text, accept_space)

    @staticmethod
    def parse(text : str, n : int = -1, accept_space : bool = False, r_data: dict = None) -> NGram:
        text = hp.clean(text, accept_space)
        text_len = len(text)

        if n == 0 or n < -1:
            print(f"Error: Invalid n", file=sys.stderr)
            exit()
        if text_len < n:
            print(f"Warning: Not enough characters to parse", file=sys.stderr)
        if n == -1 and accept_space and " " not in text:
            print(f"Warning: String doesn't contain multiple words", file=sys.stderr)
        
        ngrams, counter = hp.parse(text, n)
        
        return NGram(n, accept_space, ngrams, r_data)
    
    @staticmethod
    def cipher_text_parse(text: CipherText, n : int = -1, accept_space : bool = True, r_data: dict = None) -> NGram:
        text = text.get_text()
        return Utility.parse(text, n, accept_space, r_data)

    @staticmethod
    def log_probability_ngram(ngram: NGram):
        ngram_occurance = ngram.get_ngrams_occurance()
        reference = ngram.get_reference_data()
        probability = 0
        for temp_ngram in ngram_occurance:
            if temp_ngram in reference:
                probability += reference[temp_ngram] * ngram_occurance[temp_ngram]
            else:
                probability += math.log(1e-10)
        return probability
    
    @staticmethod
    def is_valid_weight(lst):
        if not isinstance(lst, list):
            return False
        for item in lst:
            if not isinstance(item, tuple) or len(item) != 2:
                return False
            if not isinstance(item[0], int) or not item[0] != 0 or item[0] < -1:
                return False
            if not isinstance(item[1], (int, float)) or item[1] < 0:
                return False
        return True

    @staticmethod
    def is_valid_reference(lst):
        if not isinstance(lst, dict):
            return False
        return True
    
    @staticmethod
    def log_probability_function(text: CipherText, weights: list = [(-1, 0.07), (1, 0.06), (2, 1)], 
                                 reference_files: dict = {-1: None, 1: None, 2: None, 3: None, 4: None}):
        if not Utility.is_valid_weight(weights):
            print("Error: weights must be a list of tuple of the form \{n, weight\}", file=sys.stderr)
            exit()
        if not Utility.is_valid_reference(reference_files):
            print("Error: reference_files must be a dictionaries of the form \{n\: file_name, ...\}", file=sys.stderr)
            exit()
        accept_space = text.get_has_space()
        text = text.try_decrypt()
        probability = 0
        for n in weights:
            ngram = Utility.parse(text, n[0], accept_space, reference_files[n[0]])
            if n[0] in reference_files:
                probability += Utility.log_probability_ngram(ngram) * n[1]
            else:
                print(f"Error: Reference file for n={n[0]} not found", file=sys.stderr)
                exit()
        
        return probability

    @staticmethod
    def all_english(text: CipherText):
        if not text.get_has_space():
            print("Warning: this function only works with text that contains spaces", file=sys.stderr)
        
        text = text.try_decrypt()
        
        ngrams = Utility.parse(text, -1, True)
        words = ngrams.get_ngrams()
        r_data = rd.get_eng_word()

        for word in words:
            if word not in r_data:
                return False
            
        return True
    
    @staticmethod
    def metropolis_optimization(ciphertext: CipherText, propose_mapping: Callable, iteration: int = 10000, verify: int = 6, 
                            weights: list = [(-1, 0.09), (1, 0.06), (2, 1)], 
                            reference_files: dict = {-1: None, 1: None, 2: None, 3: None, 4: None}):

        def optimizatize(ciphertext: CipherText, iteration: int = 10000, weights: list = [(-1, 0.09), (1, 0.06), (2, 1)], 
                        reference_files: dict = {-1: None, 1: None, 2: None, 3: None, 4: None}):
            log_likely = Utility.log_probability_function(ciphertext, weights, reference_files)
            for i in range(iteration):
                temp_ciphertext = copy(ciphertext)
                temp_ciphertext.set_key(propose_mapping(temp_ciphertext.get_key()))

                temp_log_likely = Utility.log_probability_function(temp_ciphertext, weights, reference_files)

                clipped_diff = max(min(temp_log_likely - log_likely, 700), -700)
                acceptance_prob = min(1, math.exp(clipped_diff))
                
                accept = random.uniform(0, 1)

                if (accept < acceptance_prob):
                    ciphertext = temp_ciphertext
                    log_likely = temp_log_likely

                    if ciphertext.get_has_space() and Utility.all_english(ciphertext):
                        return ciphertext, log_likely / 10
            return ciphertext, log_likely

        best_ciphertext = ciphertext
        max_likely = math.log(1e-100)
        
        for i in range(verify):
            temp_ciphertext, log_likely = optimizatize(copy(ciphertext), iteration, weights, reference_files)
            if max_likely < log_likely:
                best_ciphertext = temp_ciphertext
                max_likely = log_likely

        best_ciphertext, log_likely = optimizatize(copy(best_ciphertext), iteration, weights, reference_files)

        return best_ciphertext