# thinkpad-shahash
This is a small utility which checks and recomputes sha1 hashes used to validate Lenovo ThinkPad X220/T420 (and probably other Sandy Bridge ThinkPads) firmware integrity. You can hear 5 beeps twice if the firmware fails validation and you have TPM (security chip) turned on, which is pretty common for modified firmwares.

## How to get rid of 5 beeps
You need to recompute SHA1 hashes of modified firmware files in UEFI Volume 7A9354D9-0468-444A-81CE-0BF617D890DF, change RSA key and change SHA1 hashes, RSA public key and RSA signature to yours.

1. Change all the files you want in UEFI Volume 7A9354D9-0468-444A-81CE-0BF617D890DF.

2. Generate your RSA 1024 bit key with exponent=3
```
$ openssl genrsa -3 -out my_key.pem 1024
Generating RSA private key, 1024 bit long modulus
............................++++++
.......................................................++++++
e is 3 (0x3)
 
$ openssl rsa -in my_key.pem -outform der -pubout -out my_key_pub.der
writing RSA key
 
$ openssl rsa -pubin -inform der -in my_key_pub.der -text -noout
Public-Key: (1024 bit)
Modulus:
    00:e4:f7:98:41:2f:2d:a3:67:29:75:04:9d:f4:d6:
    d6:4c:fc:b6:42:37:3b:aa:d1:65:31:8b:d1:99:af:
    bb:04:dc:e0:03:08:bb:2c:28:6a:51:a7:d9:ec:fb:
    2a:af:9b:c2:5b:1a:e5:2c:12:5b:e2:37:f4:1f:fc:
    c1:64:79:48:f8:93:6a:b2:ad:ae:f5:a8:b9:40:cf:
    a2:39:be:31:6d:dd:3f:48:5e:ca:9f:12:19:5b:32:
    b9:11:1c:67:81:7b:c0:9a:08:16:0f:88:43:8c:64:
    0a:80:90:a4:1f:a7:25:f6:bb:30:e0:ef:30:36:32:
    ec:49:a2:81:af:8d:11:72:21
Exponent: 3 (0x3)
```

3. Run this script, find and replace modified checksums in the firmware using hex editor

4. Search for "TCPABIOS" string using hex editor. Right before next block (where another TCPA block starts) copy 128 bytes from the end of the block. This is RSA signature.

5. Search for FF 12 04 00, this is RSA modulus (should be right after TCPABBLK block). Replace the modulus with the modulus from your key (it always starts with 00 and is 129 bytes long).

6. Create 128 byte file with SHA1 sum of the whole TCPABIOS block excluding RSA signature (so, right from the TCPABIOS header and until lots of zeros and FF FF, excluding FF FF), padded with zeros from the beginning, and sign it with your key:
```
openssl rsautl -inkey my_key.pem -sign -in mod_sign_sha1 -raw > mod_signature
```

7. Replace the signature (last 128 bytes of TCPABIOS block).