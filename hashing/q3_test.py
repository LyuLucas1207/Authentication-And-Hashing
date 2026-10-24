import os
import time
import importlib

example = importlib.import_module("a3")

PATH_TO_DICT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'password.lst') # Replace with your own path to the dictionary of passwords
PATH_TO_FILES = os.path.dirname(os.path.abspath(__file__)) # Replace with your own path to the q3_sample files

if __name__ == "__main__":

    with open(PATH_TO_DICT, 'rt') as f:
        dictionary = [line.rstrip() for line in f if not line.startswith("#!")]

    for i in range(1, 4):
        digests_file = f"q3_sample{i}.txt"
        with open(os.path.join(PATH_TO_FILES, digests_file), 'rt') as f:
            digests = [line.rstrip() for line in f]
        with open(os.path.join(PATH_TO_FILES, f"q3_sample{i}_sol.txt"), 'rt') as f:
            passwords = [line.rstrip() for line in f]

        t0 = time.time()
        print(f"Loaded {len(digests)} digests from {digests_file}")
        password_guesses = example.offline_dictionary_attack(dictionary, digests)
        correct_guesses = sum(x == y for x, y in zip(password_guesses, passwords))

        print(f"Guessed {correct_guesses/len(passwords):.1%} in {time.time() - t0:.2f} seconds")

    # for i in range(1, 4):
    #     with open(os.path.join(PATH_TO_FILES, f"q3_grading{i}.txt"), 'rt') as f:
    #         digests = [line.rstrip() for line in f]
    #     with open(os.path.join(PATH_TO_FILES, f"q3_grading{i}_sol.txt"), 'rt') as f:
    #         passwords = [line.rstrip() for line in f]

    #     t0 = time.time()
    #     password_guesses = example.offline_dictionary_attack(dictionary, digests)
    #     correct_guesses = sum(x == y for x, y in zip(password_guesses, passwords))

    #     print(f"Guessed {correct_guesses/len(passwords):.1%} in {time.time() - t0:.2f} seconds")