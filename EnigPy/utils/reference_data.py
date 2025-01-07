import csv
import sys
import os
import math
from helper import Helper as hp

class ReferenceData:
    ENG_MONOGRAM_LFREQ = {'E': -2.192771506987658, 'A': -2.4655041025131603, 'R': -2.5795382598728414, 
                          'I': -2.5843116017405534, 'O': -2.6361714976368016, 'T': -2.6662990383924483, 
                          'N': -2.709891895981581, 'S': -2.858564998767146, 'L': -2.902369443149783, 
                          'C': -3.092507526053394, 'U': -3.315717176317756, 'D': -3.385993547919883, 
                          'P': -3.4523538433064695, 'M': -3.5022671159028254, 'H': -3.505425205724048, 
                          'G': -3.7007496266844235, 'B': -3.8766558615908546, 'F': -4.010683792252117, 
                          'Y': -4.0297372934477025, 'W': -4.350605489999138, 'K': -4.508406517555783, 
                          'V': -4.5977974316586785, 'X': -5.842355124520141, 'Z': -5.906388374752862, 
                          'J': -6.232263033660913, 'Q': -6.233790917838966}
    ENGLISH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ENG_LETTER_BY_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    
    @staticmethod
    def read_text(path_to_text: str, accept_space: bool = False):
        text = ""
        with open(path_to_text, 'r') as file:
            counter = 0
            for line in file:
                if counter > 0 and text[-1] != " ":
                    text += " " + line
                else:
                    text += line
                counter += 1

        text = hp.clean(text, accept_space)

        return text
    
    @staticmethod
    def create_reference(path_to_text: str, n: int, accept_space: bool = False, 
                         file_name: str = "untitled_reference.csv", path_to_folder: str = "enigpy/source/"):
        
        text = ReferenceData.read_text(path_to_text, accept_space)

        ngrams, counter = hp.parse(text, n)

        with open(path_to_folder + file_name, 'w') as file:
            ngrams_occurance, ngrams_sorted = hp.find_occurance(ngrams, n)

            file.write("ngram,freq\n")
            for ngram in ngrams_sorted:
                file.write(f"{ngram},{math.log(ngrams_occurance[ngram]/counter)}\n")

    @staticmethod
    def read_data(file_name: str = "untitled_reference.csv", path_to_folder: str = "enigpy/source/"):
        if not os.path.exists(path_to_folder + file_name):
            print(f"Error: Reference file {path_to_folder + file_name} not found", file=sys.stderr)
            exit()
        
        ngram_freq = {}
        with open(path_to_folder + file_name, 'r') as filein:
            csv_reader = csv.DictReader(filein)
            for row in csv_reader:
                ngram_freq[row['ngram']] = float(row['freq'])

        return ngram_freq
    
    ENG_WORD = read_data("eng_word.csv")
    ENG_WORD_LFREQ = read_data("eng_word_lfreq.csv")
    ENG_DIGRAM_LFREQ = read_data("eng_digram_lfreq.csv")
    ENG_DIGRAM_NOSPACE_LFREQ = read_data("eng_digram_nospace_lfreq.csv")
    ENG_TRIGRAM_LFREQ = read_data("eng_trigram_lfreq.csv")
    ENG_TRIGRAM_NOSPACE_LFREQ = read_data("eng_trigram_nospace_lfreq.csv")
    ENG_TETRAGRAM_LFREQ = read_data("eng_tetragram_lfreq.csv")
    ENG_TETRAGRAM_NOSPACE_LFREQ = read_data("eng_tetragram_nospace_lfreq.csv")

    @staticmethod
    def get_defult_data(n: int, accept_space: bool):
        if n == -1:
            return ReferenceData.ENG_WORD_LFREQ
        elif n == 1:
            return ReferenceData.ENG_MONOGRAM_LFREQ
        elif n == 2 and accept_space:
            return ReferenceData.ENG_DIGRAM_LFREQ
        elif n == 2:
            return ReferenceData.ENG_DIGRAM_NOSPACE_LFREQ
        elif n == 3 and accept_space:
            return ReferenceData.ENG_TRIGRAM_LFREQ
        elif n == 3:
            return ReferenceData.ENG_TRIGRAM_NOSPACE_LFREQ
        elif n == 4 and accept_space:
            return ReferenceData.ENG_TETRAGRAM_LFREQ
        elif n == 4:
            return ReferenceData.ENG_TETRAGRAM_NOSPACE_LFREQ
    
    def get_eng_word():
        return ReferenceData.ENG_WORD
