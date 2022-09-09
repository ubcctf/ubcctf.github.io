---
title: "[UTCTF 2022] Malformed Query"
date: 2022-03-13 15:47:21
author: aynakeya
---

# 0x0 Description

The problem give us a wireshark data packets files. Our goal is to analyze the packet, find the protocol used in the interaction and get the flag.

# 0x1 Analyze the protocol

in the wireshark, there is a very suspicious udp stream (3.93.213.98:9855) that gives us a command result of `ls -al`.

the connection start with a packet that contains `publickey`. 


Then server reply with a packet with a RSA publickey.

```
00000000  00 0c 01 00 00 01 00 00  00 00 00 00 09 70 75 62   ........ .....pub
00000010  6c 69 63 6b 65 79 00 00  10 00 01                  lickey.. ...
```

If we copy the first packet and send to the sever, we got a new response with a different publickey! 

This clearly shows that the server is using a special protocol to interact with client. 

Now, our goal is to figure out how is the protocol looks like.

```
from pwn import *
io = connect("3.93.213.98",9855,typ="udp")
io.send(bytes.fromhex("000c01000001000000000000097075626c69636b65790000100001"))
print(io.recv())
```

```
$ python xxx.py 
[+] Opening connection to 3.93.213.98 on port 9855: Done
b'\x00\x0c\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\tpublickey\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x137\x00\xff\xfe-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyljjH5MViK9eDX3TYlO8\nCei+rVufA+lrsw36gv/Ntv34PBXebZBC8BSwy/t0jMHnn7+9fY0zum9sMwV7A7R9\n3RWt5WppeqPyhuFNlM8DoGN5RLjTVLLKvSG2df5c8IktfDpjdrgUYDOiMMN7ANVE\nyIK+Nt+RBoGK2fkKk3NljlmmXKKP\xc0\x0c\x00\x10\x00\x01\x00\x00\x137\x00\xce\xcdU2yQZX6uHgMPXk1QSvXRsPcdWG255dBhVXK/\nrB2vAMOsD2QDMiUEa5KFgDxoBT3CH1H2nPCcXGux2j+gCpxyzzSdWrdxw64xmcGm\nrYWyC/lEygNDYc82JQJatHJSeDmz1TeA6LoY29QnKzSfrOZNvRxaB9NbbY7s9zRS\nJwIDAQAB\n-----END RSA PUBLIC KEY-----\n'
```

Further analyze the packet, we found all the packet follows a similar structure.

```
header  + sequence num + next sequence num + magic data + [length +  data  + ending] * n
4 bytes +    2 bytes   +     2 bytes       +   4 bytes  + [1 byte + n byte + 5 byte] * n
```

Note that the max length for a single message is `0xfe(254)`, if our data is more than 254 bytes, we need seperate data into 254 bytes chunks.


Here is the packet (9 bytes) client send to the server
```
00000000  00 0c 01 00 00 01 00 00  00 00 00 00 09     70 75 62   ........ .....pub
          header      seq n seq    magic data  length data
00000010  6c 69 63 6b 65 79 00 00  10 00 01                  lickey.. ...
                            ending bytes
```

here is another example packet (more than 254 bytes) received from the server
```
    00000000  00 0c 81 80 00 01 00 02    00 00 00 00 09  70 75 62   ........ .....pub
              header      seq   next seq magic data  len data
    00000010  6c 69 63 6b 65 79 00 00  10 00 01 c0 0c 00 10 00   lickey.. ........
                                ending bytes    header      seq
    00000020  01 00 00    13 37 00 ff   fe  2d 2d 2d 2d 2d 42 45 47   ....7... -----BEG
                 next seq magic data    len data
    00000030  49 4e 20 52 53 41 20 50  55 42 4c 49 43 20 4b 45   IN RSA P UBLIC KE
    00000040  59 2d 2d 2d 2d 2d 0a 4d  49 49 42 49 6a 41 4e 42   Y-----.M IIBIjANB
......
    00000120  58 39 43 30 6c 33 c0 0c  00 10 00 01 00 00 13 37   X9C0l3.. .......7
                                ending bytes
    00000130  00 ce cd 31 58 72 62 36  75 33 70 74 5a 78 4f 49   ...1Xrb6 u3ptZxOI
......
    000001E0  41 42 0a 2d 2d 2d 2d 2d  45 4e 44 20 52 53 41 20   AB.----- END RSA 
    000001F0  50 55 42 4c 49 43 20 4b  45 59 2d 2d 2d 2d 2d 0a   PUBLIC K EY-----.
```

After we receive the public key, we can encrypt command with public key, send packet to the server and get the flag.

(The encryption using OAEP scheme with sha512)


# 0x2 Final script

```
from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
import base64
io = connect("3.93.213.98",9855,typ="udp")
io.send(bytes.fromhex("000c01000001000000000000097075626c69636b65790000100001"))
print(io.recvuntil(b"-----BEGIN RSA PUBLIC KEY-----\n").hex())
public_key = io.recvuntil(b"\n-----END RSA PUBLIC KEY-----\n",drop=True).replace(b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x137\x00\xce\xcd",b"")
public_key = b"-----BEGIN RSA PUBLIC KEY-----\n"+public_key+b"\n-----END RSA PUBLIC KEY-----"
print(public_key.decode())
keyPub = RSA.importKey(public_key)
cipher = PKCS1_OAEP.new(keyPub,SHA512)
cipher_text = cipher.encrypt(b"ls")
print(len(cipher_text),cipher_text.hex())
payload = bytes.fromhex("000c01000002000000000000")+bytes.fromhex("fe")+cipher_text[:254:]+bytes.fromhex("0000100001")+bytes.fromhex("02")+cipher_text[254:256:]+bytes.fromhex("0000100001")
print(payload.hex())
io.send(payload)
print(io.recv())
```