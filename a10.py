#!/usr/bin/env python3

# ---------------------------------------------------------------
#
# CMPUT 331 Student Submission License
# Version 1.0
# Copyright 2026 Precious Ajilore
#
# Redistribution is forbidden in all circumstances. Use of this software
# without explicit authorization from the author is prohibited.
#
# This software was produced as a solution for an assignment in the course
# CMPUT 331 - Computational Cryptography at the University of
# Alberta, Canada. This solution is confidential and remains confidential
# after it is submitted for grading.
#
# Copying any part of this solution without including this copyright notice
# is illegal.
#
# If any portion of this software is included in a solution submitted for
# grading at an educational institution, the submitter will be subject to
# the sanctions for plagiarism at that institution.
#
# If this software is found in any public website or public repository, the
# person finding it is kindly requested to immediately report, including
# the URL or other repository locating information, to the following email
# address:
#
#          gkondrak <at> ualberta.ca
#
# ---------------------------------------------------------------

"""
Assignment 10
Author: Precious Ajilore
"""

from collections import Counter
from sys import flags
import glob



def normalize_text(text: str) -> str:
    """
    The purpose of this function is to normalize the text so that 
    things like a and A are treated the same.
    """
    return text.upper()

def read_text(path: str) -> str:  
    """
    This will help read sample texts and ciphertext files
    """  
    with open(path, encoding="utf8") as f:
        return normalize_text(f.read())

def extract_letters(text: str):
    """
    because in SSD i only csre about alphabetic characters
    we turn the text into a list of letters
    """
    text = normalize_text(text)
    return [char for char in text if char.isalpha()]

def ssd_from_text(text: str):
    """
    This will compute the sorted symbol distribution of a text
    """
    # we only care about letters, so we extract them first
    letters = extract_letters(text)
    total = len(letters)
    if total == 0:
        return []

    #get the counts of each letter and sort them in descending order
    counts = Counter(letters)
    #sort the counts in descending order and convert to probabilities
    sorted_counts = sorted(counts.values(), reverse=True)
    return [count/total for count in sorted_counts]

def ssd_distance(dist_a, dist_b):
    #get the maximum length of the two distributions
    max_len = max(len(dist_a), len(dist_b))
    total = 0.0

    #for each position up to the max length
    for i in range(max_len):
        #get the probability at this position
        p1 = dist_a[i] if i < len(dist_a) else 0.0
        p2 = dist_b[i] if i < len(dist_b) else 0.0

        #get the difference 
        diff = p1 - p2

        #this follows the formula for vector distance
        #which is the sum of the squared differences
        total += diff * diff
    return total



def extract_words(text: str):
    text = normalize_text(text)
    words = []
    current = []

    #for each characte in the text
    for char in text:
        if char.isalpha():
            #if its an alphabetic character we add it to the current word
            current.append(char)
        elif current:
            #if we hit a non-alphabetic character and we have a current word,
            # we join the characters to form the word and add it to the list of words
            words.append("".join(current))
            current = []

    if current:
        #if we end the text and we still have a current word, we add it to the list of words
        words.append("".join(current))

    return words


def decomposition_pattern(word: str):
    """
    for a word we want to count each distinct letter,
    sort the counts descending
    return them as a tuple

    SEEMS: S: 2, E: 2, M: 1 => (2, 2, 1)
    """

    #get the counts for each letter in the word
    counts = Counter(word)
    #return a sorted tuple of the counts in descending order
    return tuple(sorted(counts.values(), reverse=True))


def decomposition_pattern_distribution(text: str):
    """
    so this is when we build the distribution of the decomposition patters
    of a text
    so we tokenize into words, convert each word to its pattern
    coubt how often each pattern appears and divide by the total number of words
    """

    #first we extract the words from the text
    words = extract_words(text)
    total = len(words)
    if total == 0:
        return {}
    
    #get the pattern for each word
    patterns = [decomposition_pattern(word) for word in words]

    #get the counts for each pattern 
    counts = Counter(patterns)

    #key is the pattern and the value is the probability of that pattern appearing in the text
    return {pattern: count / total for pattern, count in counts.items()}


def dpd_distance(dist_a, dist_b):
    #get the set of all patterns that appear in either distribution
    patterns = set(dist_a) | set(dist_b)
    total = 0.0

    #for each pattern
    for pattern in patterns:
        #basically dist_a is a dictionary, so we use
        #get to get the probability of this pattern within that distribution
        p1 = dist_a.get(pattern, 0.0)
        p2 = dist_b.get(pattern, 0.0)

        #calculate the difference
        diff = p1 - p2

        #use the squared difference to calculate the distance
        total += diff * diff
    return total


def language_code(path: str):
    return path.split("/")[-1].split(".")[0].split("_")[1]


def best_match(score_dict: dict):
    return min(score_dict, key=score_dict.get)

def cliSSD(ciphertext: str, files):
    """
    Args:
        ciphertext (str)
        files (list of str)
    Returns:
        dict
    """

    """
    We care that the most common symbol has some probability
    the second most common symbol has some probabiloyu ad so on,
    so if english plaintext comes wierd symbols the most common
    symbol in teh ciphertext still tends to behave the most common s
    English letter frequency
    Goal is to write this function that returns a dictionary 
    mapping each file to a distance score between the sorted 
    symbol distribution of the ciphertext and the sorted 
    symbol distribution of the sample text in that file. 
    The distance score should be computed using the vector 
    distance function defined above. The lower the score, 
    the more similar the distributions are, and thus the more 
    likely it is that the ciphertext is in the same language as 
    the sample text.
    """
    # first we compute the sorted symbol distribution of the ciphertext
    ciphertext_ssd = ssd_from_text(ciphertext)

    distances = {}

    #for each file
    for path in files:
        #read the text and compute the sorted symbol distribution of the sample text
        sample_ssd = ssd_from_text(read_text(path))
        distances[path] = ssd_distance(ciphertext_ssd, sample_ssd)
    
    return distances
def cliDPD(ciphertext: str, files):
    """
    Args:
        ciphertext (str)
        files (list of str)
    Returns:
        dict

    Idea is that instead of lookig at the letter frequencies
    we look at the word structure like
    SEEMS counts are 2, 2, 1, => pattern (2, 2, 1)
    BEAMS has all distinct letters => pattern (1, 1, 1, 1, 1)
    then for the whole text we can then compute how often each 
    pattern appears among all the word tokens
    this will provide a distribution over patterns
    so the goal is to retrun the distances from the ciphertexts
    DPD to each sample file's DPD
    """
    #compute the decomposition pattern distribution of the ciphertext
    ciphertext_dpd = decomposition_pattern_distribution(ciphertext)
    distances = {}

    #for each file
    for path in files:
        #read the text and compute the decomposition pattern distribution of the sample text
        sample_dpd = decomposition_pattern_distribution(read_text(path))
        #store the distance between the two distributions in the distances dictionary
        distances[path] = dpd_distance(ciphertext_dpd, sample_dpd)

    return distances

def cliSSDTest(ciphertext_files, sampletext_files):
    """
    Args:
        ciphertext_files (list of str)
        sampletext_files (list of str)
    Returns:
        dict
    """
    result = {}

    #for each ciphertext file
    for ciphertext_file in ciphertext_files:
        #read the text of the ciphertextfile
        ciphertext = read_text(ciphertext_file)
        #compute the sorted symbol distribution distance scores 
        # between the ciphertext and each sample text file
        scores = cliSSD(ciphertext, sampletext_files)
        #store the best match (the file with the lowest distance score)
        #  in the result dictionary
        result[ciphertext_file] = best_match(scores)

    return result

def cliDPDTest(ciphertext_files, sampletext_files):
    """
    Args:
        ciphertext_files (list of str)
        sampletext_files (list of str)
    Returns:
        dict
    """
    result = {}

    #for each ciphertext
    for ciphertext_file in ciphertext_files:
        ciphertext = read_text(ciphertext_file)
        #get the decomposition pattern distribution distance scores 
        # between the ciphertext and each sample text file
        scores = cliDPD(ciphertext, sampletext_files)
        #store the best match (the file with the lowest distance score)
        result[ciphertext_file] = best_match(scores)

    return result

def generateMapping(dictionary: dict):
    """
    Args:
        dictionary (return value of cliSSDTest or cliDPDTest)
    Returns:
        A classification mapping (dict) of the ciphertexts.
        Please refer to the assignment instructions for the required format.
    """
    mapping = {}

    for ciphertext_file, sample_file in dictionary.items():
        #get the actual language code from the ciphertext file name 
        # and the predicted language code from the sample file name
        actual = language_code(ciphertext_file)
        predicted = language_code(sample_file)
        #update the mapping dictionary to count
        #how many times each (actual, predicted) pair occurs
        mapping[(actual, predicted)] = mapping.get((actual, predicted), 0) + 1

    return mapping
def generateMatrix(mapping):
    """
    Args:
        mapping (dictionary returned by generateMapping)
    Returns:
        None (prints a formatted confusion matrix)
    """
    languages = ["bg", "de", "el", "en", "es", "fr", "it", "nl", "pl", "ru"]

    header = "     " + " | ".join(languages)
    print("\n")
    print(header)
    print("   " + "-" * len(header))

    for actual in languages:
        row = [f"{mapping.get((actual, predicted), 0):>2}" for predicted in languages]
        print(f"{actual} | {' | '.join(row)}")
    print("\n") 


def test():

# Test cases for Problem 1 and Problem 2.
# Floating-point results are considered correct within an absolute tolerance of 1e-5.
# Feel free to add more test cases here 
    cipher = """fukvuvu osyxhwuyxg wxhobsuv gxrxvbepxsy ucybsbpbck ewbixty povvobs xtc ybyuv tbky povvobs xtc
ylx xcwbexus gopxskobs luwpbsokosh bdixtyorxk kywctycwuv mcsgk xntlushosh osmbwpuyobs xnexwoxstx usg ogxuk tbvvudbwuyorx fbwa pbsoybwosh kbtouv euwysxwk v
xcwbexus tbppokkobs
xcwbexus gxtokobsk bs ylx opevxpxsyuyobs bmylx tbppbs kxtcwoyj usg gxmxstx ebvotj ostvcgosh ylbkx osoyouyosh u pokkobs uk wxmxwwxg yb os ylok uwyotvx kluvv dx ugbeyxg dj ylx tbcstov bm posokyxwk utyosh csusopbckvj bs u ewbebkuv mwbp ylx csobs posokyxw mbw mbwxohs ummuowk bw mwbp u pxpdxw kyuyx
oo yb xskcwx yluy ylx xcwbexus ewbebkuv vosxk mwupxk exw kxtbsg ewbhwxkkorx ktussosh ok ugbeyxg uk ylx koshvx fbwvg kyusg uwg
ylx pbwx xmmotoxsy ylx bexwuybwk osrbvrxg ylx pbwx xmmotoxsy ylx xcwbexus yxvxtbppcsotuyobsk puwaxy fovv dx
yuos ylx ybyuv ruvcx bm ylx wxkeowuyovx gcky tbstxsywuyobs mbw kextomoxg yopx osyxwruvk
oyv
dj vxyyxw guyxg puwtl gw gx gbposotok fuk osmbwpxg dj gh nro yluy ylx ewbixty bm ylx mbcsguyobs lug sby dxxs kxvxtyxg dxtuckx oy gog sby pxxy ylx ussbcstxg twoyxwou
bs yb sbrxpdxw os tbsicstyobs foyl ylx sxylxwvusgk posokywj bm lxuvyl usg ylx xsrowbspxsy ylx tbppokkobs lxvg us osyxwsuyobsuv tbsmxwxstx uy ylx luhcx bs tvxus yxtlsbvbhoxk bkuv yb ylx tbcstov tbstxwsosh u pcvyousscuv ewbhwuppx os ylx moxvg bm dobpbvxtcvuw xshosxxwosh osgowxty utyobs ylx xtbsbpot usg kbtouv tbppoyyxx pxxyosh bs usg sbrxpdxw gxvorxwxg us beosobs bs ylx tbppokkobs ewbebkuv yb ylx tbcstov tbstxwsosh cwusocp xnevbwuyobs usg xnywutyobs osgowxty utyobs
"""
    a = cliSSD(cipher, ["texts/sample_bg.txt", "texts/sample_de.txt", "texts/sample_el.txt", "texts/sample_en.txt", "texts/sample_es.txt", "texts/sample_fr.txt", "texts/sample_it.txt", "texts/sample_nl.txt", "texts/sample_pl.txt", "texts/sample_ru.txt"])
    expected_a = {'texts/sample_bg.txt': 0.0008686304175672087, 'texts/sample_de.txt': 0.0030282241681359465, 'texts/sample_el.txt': 0.003900768672618399, 'texts/sample_en.txt': 0.0009685983479506998, 'texts/sample_es.txt': 0.0014847832596343855, 'texts/sample_fr.txt': 0.002342377137372695, 'texts/sample_it.txt': 0.0008613778129189986, 'texts/sample_nl.txt': 0.00658594015644843, 'texts/sample_pl.txt': 0.004795508346043341, 'texts/sample_ru.txt': 0.002884312599878665}
    for key, value in expected_a.items():
        assert abs(a[key] - value) < 1e-4

    b = cliDPD(cipher, ["texts/sample_bg.txt", "texts/sample_de.txt", "texts/sample_el.txt", "texts/sample_en.txt", "texts/sample_es.txt", "texts/sample_fr.txt", "texts/sample_it.txt", "texts/sample_nl.txt", "texts/sample_pl.txt", "texts/sample_ru.txt"])
    expected_b = {'texts/sample_bg.txt': 0.03760706244775398, 'texts/sample_de.txt': 0.019627307148711397, 'texts/sample_el.txt': 0.010778849211054852, 'texts/sample_en.txt': 0.004254877302061767, 'texts/sample_es.txt': 0.017505446082276693, 'texts/sample_fr.txt': 0.0120039286951674, 'texts/sample_it.txt': 0.01241955510016762, 'texts/sample_nl.txt': 0.009751349385997449, 'texts/sample_pl.txt': 0.03375909319348446, 'texts/sample_ru.txt': 0.03334088648579243}
    for key, value in expected_b.items():
        assert abs(b[key] - value) < 1e-4

    sampletext_files = sorted(glob.glob("texts/sample_*.txt"))
    ciphertext_files = sorted(glob.glob("texts/ciphertext_*.txt"))

    print("Sample files:", len(sampletext_files))
    print("Ciphertext files:", len(ciphertext_files))

    ssd_predictions = cliSSDTest(ciphertext_files, sampletext_files)
    dpd_predictions = cliDPDTest(ciphertext_files, sampletext_files)

    ssd_mapping = generateMapping(ssd_predictions)
    dpd_mapping = generateMapping(dpd_predictions)

    print("\nSSD confusion matrix:")
    generateMatrix(ssd_mapping)

    print("\nDPD confusion matrix:")
    generateMatrix(dpd_mapping)


    ssd_correct = sum(
        count for (actual, predicted), count in ssd_mapping.items()
        if actual == predicted
    )
    dpd_correct = sum(
        count for (actual, predicted), count in dpd_mapping.items()
        if actual == predicted
    )

    print(f"SSD accuracy: {ssd_correct}/50")
    print(f"DPD accuracy: {dpd_correct}/50")

    return ssd_mapping, dpd_mapping, ssd_predictions, dpd_predictions

if __name__ == "__main__" and not flags.interactive:
    test()
