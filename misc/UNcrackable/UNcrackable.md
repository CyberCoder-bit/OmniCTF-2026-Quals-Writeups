# OmniCTF 2026 Quals - UNcrackable Write-Up - Misc
Welcome to the final exam of the Hash Cracking subject in the haxxor academy

Here is your assignment:

You have 48 hours to complete the exam. Break the hash and submit omniCTF{sha256(mutated_password)}

Hash is fdec178d06a81b3b4ff199ca43082ab58b328cd799640ddac726b71fb0b3ebd0

The algorithm is unknown. It is not widely used. It was a direct submission to NIST’s SHA-3 competition and was presented among the first-round candidates in 2009.

The base wordlist used is rockyou.txt

The mutation rule is:

a) First character of the password is capitalized (if it is a letter)

b) One of the last three characters has its case toggled (if possible)

c) Three digits are appended at the end of the password

## Solution
Based on the clues, we find out that MD6-256 is an algorithm that matches the description.


**Flag: omniCTF{5c49588867efbf99e8bde3cab3a0a62315a6c99b6dd669a70e08b15749cd6179}**
