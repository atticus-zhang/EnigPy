class Helper:
    ENGLISH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ENG_LETTER_BY_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

    @staticmethod
    def clean(text: str, accept_space: bool = False):
        s = ""
        is_space = False
        
        if accept_space:
            for letter in text:
                if letter.isalpha():
                    if is_space:
                        # keep only one space when many exists side by side
                        s += " "
                        is_space = False
                    s += letter.upper()
                elif letter == " " or letter == "\t" or letter == "\n":
                    is_space = True
        else:
            for letter in text:
                if letter.isalpha():
                    s += letter.upper()

        return s

    @staticmethod
    def parse(text : str, n : int = -1):
        text_len = len(text)
        counter = 0
        ngrams = []

        if n == -1:
            # represents ngram length of n/a, i.e. parse into words
            ngrams = text.split(" ")
            counter = len(ngrams)
        else:
            for i in range(text_len - n + 1):
                ngram = text[i: i + n]
                if ngram != " " * n:
                    ngrams.append(ngram)
                    counter += 1
        return ngrams, counter
    
    @staticmethod
    def find_occurance(ngrams: list, n: int):
        ngrams_occurance = {}

        for ngram in ngrams:
            if ngram in ngrams_occurance:
                ngrams_occurance[ngram] += 1
            else:
                ngrams_occurance[ngram] = 1
        
        if n == 1:
            for letter in Helper.ENGLISH_ALPHABET:
                if letter not in ngrams_occurance:
                    ngrams_occurance[letter] = 0
        ngrams_occurance = dict(sorted(ngrams_occurance.items(), key=lambda kv: kv[1], reverse=True))

        return ngrams_occurance, list(ngrams_occurance.keys())
