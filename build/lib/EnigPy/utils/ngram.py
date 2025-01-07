import sys
from .helper import Helper as hp
from .reference_data import ReferenceData as rd

class NGram:
    def __init__(self, n: int, has_space: bool, ngrams: list, r_data: dict = None):
        self._n = n
        self._has_space = has_space
        self._ngrams = ngrams
        self._ngrams_occurance, self._ngrams_sorted = hp.find_occurance(ngrams, n)
        if not (n == -1 or (n > 0 and n < 5)) and not r_data:
            print(f"Error: No reference data provided", file=sys.stderr)
            print("The enigpy library only provides probabilities for up to n = 4. If you wish to use longer ngrams, please construct your own!", 
                file=sys.stderr)
            exit()
        elif r_data:
            self._reference_data = r_data
        else:
            self._reference_data = rd.get_defult_data(n, has_space)

    def get_n(self):
        return self._n  

    def get_has_space(self):
        return self._has_space   

    def get_ngrams(self):
        return self._ngrams   

    def get_ngrams_occurance(self):
        return self._ngrams_occurance

    def get_ngrams_sorted(self):
        return self._ngrams_sorted

    def get_reference_data(self):
        return self._reference_data
