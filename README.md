# authentication-and-hashing

认证与口令散列。这份材料说明散列为什么不可逆却仍能被字典比对认出来，加盐和工作因子如何改变破解的代价，以及没有完整性校验的令牌为什么还能被改写。

Authentication and password hashing. These notes explain why a hash cannot be inverted yet still falls to a dictionary comparison, how a salt and a work factor change the cost of cracking, and why a token with no integrity check can still be rewritten.

## 要回答的问题

1. **辨认散列函数。** 三个摘要分别由哪种 SHA 函数生成，依据是什么，口令是什么。
2. **bcrypt 摘要。** 三个 bcrypt 摘要用的是什么函数，盐是否相同，哪一个计算得更久。
3. **字典攻击 bcrypt。** 给定口令字典和一组 bcrypt 摘要，还原出每个摘要对应的口令。
4. **难易比较。** `q3_sample1`–`q3_sample3` 里哪一份最容易破，哪一份最难，为什么。
5. **暴力破解上限。** 一天之内，本机对 bcrypt（4 轮）和 SHA-256 各能穷举多长的口令。
6. **在线计时攻击。** 服务器逐字符比较口令并泄露耗时。用这个时间差把口令读出来。
7. **双因素认证。** 选一个真实服务，说明它支持哪些第二因素，攻击者怎样绕过。
8. **UBC 认证。** 对照 NIST 的建议，评论 CWL 的两条口令政策。
9. **CBC 令牌。** 把服务器发出的 `guest` 令牌改成 `admin`。

## Questions

1. **Identify the hash function.** For each of three digests, name the SHA function that produced it, the evidence, and the password.
2. **bcrypt digests.** Which function produced the three bcrypt digests, whether the salts match, and which took longer to compute.
3. **Dictionary attack on bcrypt.** Given a password dictionary and a set of bcrypt digests, recover the password behind each digest.
4. **Easiest and hardest.** Which of `q3_sample1`–`q3_sample3` is the easiest to break and which the hardest, and why.
5. **Brute-force ceiling.** The longest password this machine can exhaust in under a day, for bcrypt (4 rounds) and for SHA-256.
6. **Online timing attack.** The server compares the password character by character and leaks how long the check took. Use that difference to read the password.
7. **Two-factor authentication.** Pick a real service, name the second factors it supports, and show how an attacker could circumvent them.
8. **Authentication at UBC.** Comment on two CWL password policies against the matching NIST recommendation.
9. **CBC token.** Turn a `guest` token from the server into an `admin` token.

Questions 3, 6, and 9 are coded in `hashing/a3.py`. Questions 1, 2, 4, 5, 7, and 8 are written up in the PDF, and Question 1 also has a standalone script in `assignments/q1.py`.

## 散列与口令

散列把任意长的输入收成固定长的摘要，不可逆，且输入略变摘要就全变。它本身没有密钥，所以同一口令每次得到同一摘要。

A hash maps an input of any length to a fixed-length digest. It cannot be inverted, and a small change in the input changes the whole digest. It has no key, so one password always gives the same digest.

### 辨认 SHA 函数 / Identifying a SHA function

一个十六进制字符是 4 比特，所以摘要的比特数是字符数的四倍。64、56、40 个字符分别是 256、224、160 比特。这只能缩到一族：SHA-256、SHA3-256、SHA-512/256 都是 64 字符，SHA-224、SHA3-224、SHA-512/224 都是 56 字符。40 字符的常见 SHA 只有 SHA-1。

One hex character is 4 bits, so a digest's bit length is four times its character count. 64, 56, and 40 characters are 256, 224, and 160 bits. That only narrows it to a family: SHA-256, SHA3-256, and SHA-512/256 are all 64 characters, and SHA-224, SHA3-224, and SHA-512/224 are all 56. SHA-1 is the only common SHA with 40.

长度不能单独定出函数。作业保证口令都在字典里，于是用每个候选函数散列每个字典词，和摘要比对。哪个函数、哪个词命中，就同时确定了算法和口令。

Length alone does not name the function. Since every password is in the dictionary, each dictionary word is hashed with every length-matched candidate and compared with the digest. The match names both the algorithm and the password.

### 盐与工作因子 / Salt and work factor

bcrypt 摘要是 Modular Crypt Format：`$2b$` 前缀、两位工作因子、22 字符的盐，然后是散列值。前缀相同说明是 bcrypt；盐字段不同说明加了不同的盐，相同口令也得到不同摘要，查表彩虹表失效。工作因子是对数的，代价按 \(2^{\text{cost}}\) 增长，所以 cost 8 的摘要比 cost 6 的约慢四倍。

A bcrypt digest is in Modular Crypt Format: the `$2b$` prefix, a two-digit cost, a 22-character salt, then the hash. The shared prefix marks bcrypt; different salt fields mean different salts, so equal passwords still give different digests and a precomputed table is useless. The cost is logarithmic — work grows as \(2^{\text{cost}}\) — so a cost-8 digest is about four times slower than a cost-6 one.

字典攻击 bcrypt 时，摘要前 29 个字符（前缀、cost、盐）决定一次 bcrypt 计算的设置。设置相同的摘要可以共用对同一口令的一次散列，这就是 `offline_dictionary_attack` 按设置分组的原因。

For the dictionary attack, the first 29 characters of a digest (prefix, cost, salt) fix the bcrypt setting. Digests that share a setting share one hash per candidate password, which is why `offline_dictionary_attack` groups by setting.

### 字典 vs 暴力 / Dictionary vs brute force

字典攻击只试一张词表，命中与否取决于口令在不在表里。暴力攻击穷举整个字符空间，代价是 \(|\Sigma|^{L}\)，由字符集大小和口令长度决定，而每次尝试的单价由散列速度决定。bcrypt 故意很慢，所以同样一天内能穷举的长度远小于 SHA-256。

A dictionary attack tries one wordlist; success depends on whether the password is in it. A brute-force attack exhausts the whole character space at cost \(|\Sigma|^{L}\), set by the alphabet size and the length, while the per-guess price is set by the hashing speed. bcrypt is deliberately slow, so the length it can exhaust in a day is far shorter than SHA-256's.

### 在线计时 / Online timing

离线攻击握有摘要，自己任意散列。在线攻击只能问服务器，还可能被限速。若服务器逐字符比较并在首个不匹配处返回，正确前缀越长耗时越久。按这个耗时逐位选出口令，就把一个 \(|\Sigma|^{L}\) 的搜索降成 \(|\Sigma|\times L\)。噪声靠多次测量取中位数或多数压下去。

An offline attack holds the digest and hashes freely. An online attack can only ask the server and may be rate-limited. If the server compares character by character and returns at the first mismatch, a longer correct prefix takes longer. Choosing each position by that time turns a \(|\Sigma|^{L}\) search into \(|\Sigma|\times L\). Noise is suppressed by taking a median or majority over repeated measurements.

### CBC 令牌 / CBC token

Q9 的令牌形如 `name=<name>&pwd=<pwd>&role=guest&code=<code>`，用 AES-CBC 加密且无完整性校验。CBC 解密时，每组明文是「AES 解密的结果」异或上一组密文。改一字节上一组密文，就按位改了下一组明文，代价是上一组自身解密成乱码。把这段乱码放在无关紧要的字段里，就能把 `guest` 翻成 `admin` 而不需要密钥。

The Q9 token is `name=<name>&pwd=<pwd>&role=guest&code=<code>`, encrypted with AES-CBC and no integrity check. On CBC decryption each plaintext block is the AES-decrypted block XORed with the previous ciphertext block. Flipping a byte of the previous ciphertext flips the same byte of the next plaintext, at the cost of garbling the previous block. Parking that garble in a field that does not matter turns `guest` into `admin` without the key.

## 文件

| 路径 | 内容 |
| --- | --- |
| `a3-cpen442-26w1.pdf` | 作业说明 |
| `a3-cpen442-26w1-student-template.tex` | 解答模板，覆盖第 1、2、4、5、7、8 题 |
| `a3-cpen442-26w1-student-template.pdf` | 模板编译结果 |
| `assignments/q1.py` | 第 1 题：按摘要长度定候选，再用字典比对还原口令 |
| `hashing/a3.py` | 第 3、6、9 题的作答函数 |
| `hashing/password.lst` | 口令字典 |
| `hashing/q3_sample{1,2,3}.txt` | 第 3 题的 bcrypt 摘要样例 |
| `hashing/q3_sample{1,2,3}_sol.txt` | 对应口令，用于自测 |
| `hashing/q3_test.py` | 按样例给 `offline_dictionary_attack` 打分 |
| `hashing/q5_test.py` | 测本机 bcrypt 与 SHA-256 的散列速度 |
| `hashing/q6_server.py` | 第 6 题的服务器：带随机延迟的口令校验 |
| `hashing/q6_test.py` | 为在线计时攻击打分 |
| `hashing/q9_server.py` | 第 9 题的服务器：发行并校验 CBC 令牌 |
| `hashing/q9_test.py` | 为令牌改写打分 |

## Files

| Path | Contents |
| --- | --- |
| `a3-cpen442-26w1.pdf` | Handout |
| `a3-cpen442-26w1-student-template.tex` | Answer template, covering Questions 1, 2, 4, 5, 7, 8 |
| `a3-cpen442-26w1-student-template.pdf` | Compiled template |
| `assignments/q1.py` | Question 1: fix candidates by digest length, then recover the password by dictionary comparison |
| `hashing/a3.py` | Answer functions for Questions 3, 6, 9 |
| `hashing/password.lst` | Password dictionary |
| `hashing/q3_sample{1,2,3}.txt` | Sample bcrypt digests for Question 3 |
| `hashing/q3_sample{1,2,3}_sol.txt` | Matching passwords, for self-checking |
| `hashing/q3_test.py` | Scores `offline_dictionary_attack` on the samples |
| `hashing/q5_test.py` | Measures this machine's bcrypt and SHA-256 hashing speed |
| `hashing/q6_server.py` | Question 6 server: password check with a random delay |
| `hashing/q6_test.py` | Scores the online timing attack |
| `hashing/q9_server.py` | Question 9 server: issues and checks CBC tokens |
| `hashing/q9_test.py` | Scores the token rewrite |
