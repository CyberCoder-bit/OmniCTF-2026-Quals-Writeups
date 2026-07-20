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

### Step 1:
First, we generate a mutated wordlist from rockyou.txt using [mutate_bases.py](mutate_bases.py) and store the target using the following command:

```bash
python3 mutate_bases.py rockyou.txt > mutated_bases.txt
printf '%s\n' \
'fdec178d06a81b3b4ff199ca43082ab58b328cd799640ddac726b71fb0b3ebd0' \
> target.txt
```
### Step 2:
Next, we use hashcat to crack the hash:
```bash
./hashcat.exe \
  -m 34600 \
  -a 6 \
  target.txt \
  mutated_bases.txt \
  '?d?d?d' \
  -O \
  -w 4 \
  -d 1,3 \
  --session uncrackable-win \
  --status \
  --status-timer 10
```
### Step 3:
We then recover the password:
```bash
./hashcat.exe -m 34600 target.txt --show | head -n1 | cut -d: -f2-
```

And calculate the sha256 hash of it:
```bash
echo -n 'Gm@r$d3N667' | sha256sum
```
Output: 5c49588867efbf99e8bde3cab3a0a62315a6c99b6dd669a70e08b15749cd6179  -

**Flag: omniCTF{5c49588867efbf99e8bde3cab3a0a62315a6c99b6dd669a70e08b15749cd6179}**

## Summary
- Algorithm: ```MD6-256```
- Mutated password: ```Gm@r$d3N667```
- Flag: ```omniCTF{5c49588867efbf99e8bde3cab3a0a62315a6c99b6dd669a70e08b15749cd6179}```
