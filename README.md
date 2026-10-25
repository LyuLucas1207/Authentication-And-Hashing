# Authentication and password hashing

These notes explain why a hash cannot be inverted yet still falls to a dictionary comparison, how a salt and a work factor change the cost of cracking, and why a token with no integrity check can still be rewritten.

## Questions to answer

1. **Identify the hash function.** For each of three digests, name the SHA function that produced it, the evidence, and the password.
2. **bcrypt digests.** Which function produced the three bcrypt digests, whether the salts match, and which took longer to compute.
3. **Dictionary attack on bcrypt.** Given a password dictionary and a set of bcrypt digests, recover the password behind each digest.
4. **Easiest and hardest.** Which of `q3_sample1`–`q3_sample3` is the easiest to break and which the hardest, and why.
5. **Brute-force ceiling.** The longest password this machine can exhaust in under a day, for bcrypt (4 rounds) and for SHA-256.
6. **Online timing attack.** The server compares the password character by character and leaks how long the check took. Use that difference to read the password.
7. **Two-factor authentication.** Pick a real service, name the second factors it supports, and show how an attacker could circumvent them.
8. **Authentication at UBC.** Comment on two CWL password policies against the matching NIST recommendation.
9. **CBC token.** Have the server CBC-encrypt a `super_admin` message, then truncate the ciphertext so the parsed role is `super_admin`.

The code for Questions 3, 6, and 9 is in `hashing/a3.py`. Questions 1, 2, 4, 5, 7, and 8 are written in the PDF. Question 1 also has a standalone script, `assignments/q1.py`.

## Hashing and passwords

A hash maps an input of any length to a fixed-length digest. It cannot be inverted, and a small change in the input changes the whole digest. It has no key, so one password always gives the same digest.

### Identifying a SHA function

One hexadecimal character is 4 bits, so a digest's bit length is four times its character count. Lengths of 64, 56, and 40 characters are 256, 224, and 160 bits. That only narrows the function to a family: SHA-256, SHA3-256, and SHA-512/256 are all 64 characters, and SHA-224, SHA3-224, and SHA-512/224 are all 56. SHA-1 is the only common SHA function with 40 characters.

Length alone does not name the function. The assignment guarantees that every password is in the dictionary, so each dictionary word is hashed with every candidate and compared with the digest. The function and the word that match identify both the algorithm and the password.

### Salt and work factor

A bcrypt digest is in Modular Crypt Format: a `$2b$` prefix, a two-digit cost, a 22-character salt, then the hash. A shared prefix means bcrypt. Different salt fields mean different salts, so the same password still produces different digests and a rainbow table is useless. The cost is logarithmic: the work grows as \(2^{\text{cost}}\), so a cost-8 digest is about four times slower than a cost-6 digest.

In the bcrypt dictionary attack, the first 29 characters of a digest (prefix, cost, and salt) fix the settings for one bcrypt computation. Digests with the same settings can share one hash of a candidate password. That is why `offline_dictionary_attack` groups by those settings.

### Dictionary and brute force

A dictionary attack tries one word list. It succeeds only if the password is in that list. A brute-force attack exhausts the whole character space at a cost of \(|\Sigma|^{L}\), set by the alphabet size and the password length. The price of each guess is set by the hashing speed. bcrypt is deliberately slow, so the length it can exhaust in one day is far shorter than the length SHA-256 can exhaust.

### Online timing

An offline attack holds the digest and can hash freely. An online attack can only ask the server. A wrong length returns virtual time 0, so the length is the first probe from 5 to 10 that returns a positive time. A wrong guess at the current character is checked exactly \(n\) times, and each check adds 1 to 4. Time equal to \(n\) means the guess stopped there, so that character is rejected. Time greater than \(4n\) means the server checked further, so that character is accepted. Any time in between is measured again. The last character is tried until the server returns true.

### CBC token

Question 9 builds the desired message before any encryption. The message is `name=alice&pwd=123&role=super_admin`, followed by its SHA-256 digest and PKCS#7 padding out to a block boundary. That suffix is placed inside the password, so the server CBC-encrypts it and then appends `&role=guest`. Only the ciphertext blocks that cover the message, digest, and padding are kept. CBC decryption of those leading blocks depends only on the IV and those blocks, so the prefix is unchanged. After the server removes the padding, the last 32 bytes match the digest and the parsed role is `super_admin`.

## Files

| Path | Contents |
| --- | --- |
| `a3-cpen442-26w1.pdf` | Assignment handout |
| `a3-cpen442-26w1-student-template.tex` | Answer template for Questions 1, 2, 4, 5, 7, and 8 |
| `a3-cpen442-26w1-student-template.pdf` | Compiled template |
| `assignments/q1.py` | Question 1: choose candidates by digest length, then recover the password by dictionary comparison |
| `hashing/a3.py` | Answer functions for Questions 3, 6, and 9 |
| `hashing/password.lst` | Password dictionary |
| `hashing/q3_sample{1,2,3}.txt` | Sample bcrypt digests for Question 3 |
| `hashing/q3_sample{1,2,3}_sol.txt` | Matching passwords, for self-checking |
| `hashing/q3_test.py` | Scores `offline_dictionary_attack` on the samples |
| `hashing/q5_test.py` | Measures this machine's bcrypt and SHA-256 hashing speed |
| `hashing/q6_server.py` | Question 6 server: password check with a random delay |
| `hashing/q6_test.py` | Scores the online timing attack |
| `hashing/q9_server.py` | Question 9 server: issues and checks CBC tokens |
| `hashing/q9_test.py` | Scores the token rewrite |
