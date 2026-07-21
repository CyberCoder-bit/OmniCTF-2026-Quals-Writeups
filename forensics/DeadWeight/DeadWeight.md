# OmniCTF 2026 Quals - DeadWeight Write-Up - Forensics
Author: Masquerade

Well, well, well... This one is tricky and hard to beat. Let's take a second to relax. Here it comes! I managed to delete THE flag from the system, muhahaha, but... I still remember the times when I used axel to get my beloved flag. Enough with the story—provide the answers to the questions below. File is: https://mega.nz/file/O6BzGKTY#bssfLGqOF5wVWh6RVJOq-yN8CgAi2CNVVMWSkXas3PA MD5(second flag)=b029aefa19e1889303614610be7d3295

## Solution

We are given a memory dump, and I used Volatility3 to analyze it. I renamed the file to deadweight.raw.

**Basic Reconnaissance**

First, I do some basic reconnaissance using Volatility.
```bash
vol -f deadweight.raw windows.pslist > pslist.txt 
vol -f deadweight.raw windows.psscan > psscan.txt 
vol -f deadweight.raw windows.pstree > pstree.txt 
vol -f deadweight.raw windows.cmdline > cmdline.txt
```

**Question 1:**
> What is the SID (Security Account Identifier) of the user who tried to delete the flag? (Ex. OmniCTF{ssid})

To find the SID of the user who tried to delete the flag we first dump out all the processes.
```bash
cat pslist.txt
```
A significant output we see is Command Prompt, which could have been used to remove the flag:
```bash
8924    2892    conhost.exe     0xc187bc811340  4       -       1       False   2025-06-04 19:28:57.000000 UTC  N/A     Disabled
```
Next we try to check all the SIDs for this process:
```bash
vol -f deadweight.raw windows.getsids --pid 8924
```
Output:
```bash
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished
PID     Process SID     Name

8924    conhost.exe     S-1-5-21-3266328033-1872285240-1484667356-1001  Masquerade
8924    conhost.exe     S-1-5-21-3266328033-1872285240-1484667356-513   Domain Users
8924    conhost.exe     S-1-1-0 Everyone
8924    conhost.exe     S-1-5-114       Local Account (Member of Administrators)
8924    conhost.exe     S-1-5-32-544    Administrators
8924    conhost.exe     S-1-5-32-545    Users
8924    conhost.exe     S-1-5-4 Interactive
8924    conhost.exe     S-1-2-1 Console Logon (Users who are logged onto the physical console)
8924    conhost.exe     S-1-5-11        Authenticated Users
8924    conhost.exe     S-1-5-15        This Organization
8924    conhost.exe     S-1-5-113       Local Account
8924    conhost.exe     S-1-5-5-0-182777        Logon Session
8924    conhost.exe     S-1-2-0 Local (Users with the ability to log in locally)
8924    conhost.exe     S-1-5-64-10     NTLM Authentication
8924    conhost.exe     S-1-16-8192     Medium Mandatory Level
```
The most significant user here is Masquerade. Therefore, after trying it, we see the final answer is: **OmniCTF{S-1-5-21-3266328033-1872285240-1484667356-1001}**.

**Question 2:**
> When did the user delete the flag.txt? (Ex:OmniCTF{07/02/2025 7:20})
We can look at the console history by running this line of code:
```bash
jason@MainXuComputer:/mnt/c/Users/linaw/Downloads$ vol -f deadweight.raw windows.consoles.Consoles
```
We notice one interesting line:
```bash
C:\$Recycle.Bin>dir S-1-5-21-3266328033-1872285240-1484667356-1001
 Volume in drive C has no label.
 Volume Serial Number is A2C6-3030

 Directory of C:\$Recycle.Bin\S-1-5-21-3266328033-1872285240-1484667356-1001

06/04/2025  10:37 PM               106 $IBZOM62.txt
07/07/2024  12:47 PM               110 $IZO4D5I.exe
               2 File(s)            216 bytes
               0 Dir(s)  214,832,959,488 bytes free
```
Since $I... files are metadata in the recycle bin, the answer should be **OmniCTF{06/04/2025 10:37}**.

**Question 3:**
> What is the accidentally malicious file present in the filesystem? (OmniCTF{name.extension})

To solve this, first I looked at ```pslist.txt``` and noticed a suspicious application with 91 instances.:
```bash
3300    2896    explorer.exe    0xc187bb5e8080  91      -       1       False   2024-07-07 09:28:32.000000 UTC  N/A     Disabled
````
But when I tried submitting OmniCTF{explorer.exe}, it failed.

To solve this, I dumped out all the strings and searched for applications in them:
```bash
strings -a -n 5 deadweight.raw > deadweight.ascii.txt
strings -el -n 5 deadweight.raw > deadweight.utf16.txt
grep -Ein 'explorer.exe' deadweight.ascii.txt deadweight.utf16.txt > applications.txt
cat applications.txt
```
Searching through them, I found:
```bash
deadweight.ascii.txt:892361:Erro 404!system32\iexplorer.exeExplorer
deadweight.ascii.txt:1255043:\iiexplorer.exed
deadweight.ascii.txt:1590693:\iexplorer.exe" HELLO_E7848FBB-831E-43a4-AEEE-71C0A3C52EEA_SP
deadweight.ascii.txt:2232560:\iexplorer.exeY
```
The regular Explorer application should be iexplore.exe instead of iexplorer.exe; thus, the answer is **OmniCTF{iexplorer.exe}**.

**Question 4:**
> What is the first flag? (Flag format: CTF{funny_words})

In the description, it says, "I still remember the times when I used axel to get my beloved flag." Axel is a tool used to download things, so I decided to search the memdump of console for links.

```bash
strings -el -n 4 pid.8924.dmp | grep -iE 'https?://'
```

I see 2 interesting lines:
```
C:\Users\Masquerade\Downloads\Flag.txt|https://pastebin.com/dl/egKYMmM4|pid:8888,ProcessStart:133935394035944728
C:\Users\Masquerade\Downloads\Flag.txt|https://pastebin.com/dl/egKYMmM4|pid:8888,ProcessStart:133935394035944728
```

So then I go to https://pastebin.com/egKYMmM4 and can see the first flag in the comments:
<img width="1072" height="947" alt="image" src="https://github.com/user-attachments/assets/0e3caffc-1462-4e58-b233-b0faa2f11729" />

The final answer is: **CTF{MAsquerade_IS_drunk}**.
**Question 5:**
> What is the second flag? (Flag format: ctf{sha256})

The second flag is encrypted using this...

```python
##Is this the flag???!??Idk man...I am calling Andrei here.I only do forensics 
 
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
 
def two_des_encrypt(message: bytes, key1: bytes, key2: bytes) -> bytes:
    padded_msg = pad(message, DES.block_size)
    cipher1 = DES.new(key1, DES.MODE_ECB)
    intermediate = cipher1.encrypt(padded_msg)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    ciphertext = cipher2.encrypt(intermediate)
    return ciphertext
 
flag = b'ctf{not_real_flag}' # format: sha256
key1 = flag[:8]
key2 = flag[-8:]
middle = flag[8:-8]  
ciphertext = two_des_encrypt(middle, key1, key2) # 2ac5e1b3799e3a0e9c6d6be856a33509b04a12f01b73ad0cf0d6af1225c933c528c65a6b30b5fe76fb62df849e606c7d852a8f9270538a9f
msg = b"supersaferight?"
ciphertext_msg = two_des_encrypt(msg, key1, key2) # 57bd461497e572b0c5ec06c12d1ed8ce
```

## Summary:
Q1 = OmniCTF{S-1-5-21-3266328033-1872285240-1484667356-1001}
Q2 = OmniCTF{06/04/2025 10:37} 
Q3 = OmniCTF{iexplorer.exe} 
Q4 = CTF{MAsquerade_IS_drunk}
Q5 = ctf{a4062225bc93279ef48b44c6710079649a36b66755c56fc0dd7e7098dd266828}
