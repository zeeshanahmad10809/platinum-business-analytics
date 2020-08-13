import string
import nltk
from nltk.tokenize import sent_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer


def remove_punctuations(text):
    text = text.strip()
    text = text.strip().encode('ascii', 'replace').decode('utf-8')
    text = text.replace('-', ' ')
    text = text.replace('?', "'")
    for ch in text:
        if not ch.isalpha():
            if ch is not "'" and ch is not " ":
                text = text.replace(ch, '')

    return text

def convert_lower(text):
    return text.lower()

def remove_whitespaces(text):
    return text.strip()

def negation_handling(text):
    negation_dict = {"amn't": "am not",
                        "aren't": "are not",
                        "can't": "can not",
                        "couldn't": "could not",
                        "didn't": "did not",
                        "doesn't": "does not",
                        "don't": "do not",
                        "gon't": "go not",
                        "hadn't": "had not",
                        "hasn't": "has not",
                        "haven't": "have not",
                        "isn't": "is not",
                        "shalln't": "shall not",
                        "shouldn't": "should not",
                        "wasn't": "was not",
                        "weren't": "were not",
                        "won't": "will not",
                        "wouldn't": "would not"}
    negation_keys = list(negation_dict.keys())

    tokens = text.split()
    for i in range(len(tokens)):
        if tokens[i] in negation_dict.keys():
            tokens[i] = negation_dict[tokens[i]]
    try:
        tokens.remove('')
    except:
        pass
    return ' '.join(tokens)



def tokenization(text):
    return nltk.word_tokenize(text)

def remove_token_whitespaces(tokens):
    for i in range(len(tokens)):
        tokens[i] = tokens[i].strip()

    return tokens

def remove_token_punctuation(tokens):
    for i in range(len(tokens)):
        for ch in tokens[i]:
            if ch in string.punctuation:
                tokens[i] = tokens[i].replace(ch, '')
    if tokens.count('') > 0:
        tokens.remove('')
    return tokens


def remove_stopwords(tokens):
    stop_words = stopwords.words('english')
    stop_words.remove('not')
    stop_words.remove('nor')

    new_tokens = [word for word in tokens if not word in stop_words]

    return new_tokens


def lemmatize(tokens):
    lemmatizer = WordNetLemmatizer()
    for i in range(len(tokens)):
        tokens[i] = lemmatizer.lemmatize(tokens[i])

    return tokens


def sentence_tokenizer(paragraph):
    return sent_tokenize(paragraph)

def preprcess_sentence(sentence):
    #sentence = remove_punctuations(sentence)
    sentence = convert_lower(sentence)
    sentence = remove_whitespaces(sentence)
    sentence = negation_handling(sentence)
    sentence = tokenization(sentence)
    #sentence = remove_token_punctuation(sentence)
    #sentence = remove_stopwords(sentence)
    sentence = lemmatize(sentence)
    return sentence

def preprocess_text(paragraph):
    sentences_tokens = sent_tokenize(paragraph)
    for i in range(len(sentences_tokens)):
        sentences_tokens[i] = preprcess_sentence(sentences_tokens[i])
        if sentences_tokens[i].count(' ') > 0:
            sentences_tokens[i].remove(' ')
        if sentences_tokens[i].count('') > 0:
            sentences_tokens[i].remove('')
    if sentences_tokens.count([]) > 0:
        sentences_tokens.remove([])
    return sentences_tokens