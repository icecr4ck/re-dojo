---
authors:
  - icecr4ck
title: Flare-On 9 solutions (part 4)
date: 2022-11-13
tags:
  - Challenge
  - Flare-On
---

This blog post details the solutions of the challenges 9 to 11 of the Flare-On 9.

<!--more-->

{{< toc >}}

Here are the links to the other solutions:
- [part 1](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-1/) for challenges 1 to 4;
- [part 2](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-2/) for challenges 5 to 7;
- [part 3](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-3/) for challenge 8.

## Challenge 9 - encryptor

### Description

```md
You're really crushing it to get this far. This is probably the end for you. Better luck next year!
```

Two files are given for this challenge: a PE executable and what seems to be an encrypted file.
```bash
$ file flareon.exe SuspiciousFile.txt.Encrypted
flareon.exe:                  PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows
SuspiciousFile.txt.Encrypted: data
```

### First look
When executed, the binary waits for a command line parameter: a valid filename ending with `.EncryptMe`.

```powershell
PS C:\Users\User\Desktop> .\flareon.exe
usage: flareon path [path ...]
PS C:\Users\User\Desktop> .\flareon.exe .\Test.txt.EncryptMe
.\Test.txt.EncryptMe
1 File(s) Encrypted
```

After the execution, two files are created:
- `Test.txt.Encrypted` corresponding to the encrypted version of our input file;
- `HOW_TO_DECRYPT.txt` is the ransomware note (see the contents below).

```md
~*~*~* The FLARE-ON Encryptor ~*~*~*

All your files have been encrypted with a powerful combination of
symmetric and asymmetric cryptography. Do not tamper with the encrypted files.
It is of no use and will only risk corrupting your data.

To get your files decrypted send lots of cryptocurrency over Tor.

You'll need to copy and paste us these values to get your key.

<9f18776bd3e78835b5ea24259706d89cbe7b5a79010afb524609efada04d0d71170a83c853525888c942e0dd1988251dfdb3cd85e95ce22a5712fb5e235dc5b6ffa3316b54166c55dd842101b1d77a41fdcc08a43019c218a8f8274e8164be2e857680c2b11554b8d593c2f13af2704e85847f80a1fc01b9906e22baba2f82a1,
d9a288e5743484a7dc040d14b3e04ca6f6967656c085f8a9c53aab7bfb0f6beee7e101ba27a900f340754daf701b0964d479bc55f49a1c871e04c6da3dc3e6ee857116004f3eeb00866c45e48eb202535de5dc4716a54c39835d20dbdf2c9da56af8f9edbdd8786a5e507e4215c097be075ef4601f67071685461fdbd22926c1,
368f92b2e96b2a212a32984d3adee85d1e9e90cab6602c44377a47541b4b89f9e13cc353612d8cba9319794f06dcc4b4371c9730143b867b937845b709b729dcb62fe5f5fc36cd22616291c3d6fac2189c5ff4e525aebf85041fccbd068b7f5c39dea6d72fd31a21d033d0f4e7e4b2fe156e565a0d0331f85792acc0eaa9394a>
```

The goal of the challenge is to analyze the executable in order to decrypt `SuspiciousFile.txt.Encrypted`.

### Static analysis

#### Overview

After opening the executable in our favorite disassembler, we can see there is no obfuscation at all and the code seems to be easy to read. Here is what it does.
1. Resolve the `RtlGenRandom` Windows API.
2. Call a function (at `0x4021D0`) to initialize some large buffers (we will come back to this one in the next section).
3. Open the file given as command line parameter.
4. Generate a random encryption key (via `RtlGenRandom()`).
5. Encrypt the file contents using the random key. According to a constant of the encryption algorithm and a bit of dynamic analysis, the algorithm seems to be ChaCha20.
6. Use several buffers initialized at step 2 to (maybe?) encrypt the ChaCha20 key.
7. Write some of these large buffers and the result of the previous step after the encrypted file contents.

#### Analysis of the function at `0x4021d0`

The ransomware note gives us a hint regarding the purpose of this function, as files "have been encrypted with a powerful combination of symmetric and asymmetric cryptography". We already know that ChaCha20 is used and the latter is a symmetric algorithm so this function is likely an implementation of an asymmetric algorithm.

Without a surprise, the first that came to my mind is RSA (see [here](https://www.geeksforgeeks.org/rsa-algorithm-cryptography/) for a quick remainder on the algorithm). This cryptography algorithm is based on modular exponentiation and can use several key sizes, the most popular are 1024, 2048 and 4096 bits. Thus, the first thing I did is looking at the size of the buffers processed by our mystery function.

At first, two random buffers of 64 bytes (or 512 bits) are generated using `RtlGenRandom()`. Several checks are done on these buffers (especially by the function at `0x401DF2`) and if the checks are not verfied, new buffers are randomly generated, and so on. 

If we compare this with RSA, the initialization of RSA 1024-bit also requires two numbers of 512 bits (`p` and `q`). Both numbers have to be prime numbers, this property can be verified using a [primality test](https://en.wikipedia.org/wiki/Primality_test). Looking more closely at the function doing the checks (at `0x401DF2`), we understand this is actually an implementation of the [Miller-Rabin](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test) primality test.

At this point, RSA 1024-bit seems to be a good candidate for our mystery function, but we have to confirm this hypothesis by looking at how the two 512-bit prime numbers are processed next. 

After a bit of static analysis, here is what my IDA decompilation output looks like and this confirms our hypothesis.

{{< figure src="/images/flareon9/Challenge_9_rsa_function.png" >}}

Finally, the RSA private key is generated from `phi(n)` and the exponent `e = 0x10001`. 

### Decrypting the suspicious file

If we go back to the step where the ChaCha20 encryption key is (maybe?) encrypted using RSA, we understand that the modular exponentiation is done using the private key `d` instead of the public exponent `e`. In other words, the ChaCha20 key is only signed but not encrypted.

As the signed ChaCha20 key as well as the modulus `n` are written at the end of the encrypted file, we can easily retrieve the ChaCha20 key by doing the modular exponentiation of the signed ChaCha20 key using the public exponent `e` and the modulus `n`.

There were several ways to perform this, I chose to use miasm to emulate the modular exponentiation function. My script is available on [GitHub](https://github.com/icecr4ck/write-ups/blob/master/FlareOn-9/Challenge_9_encryptor/decrypt_file.py).

After running the script, we get the following result.
```bash
$ python decrypt_file.py flareon.exe SuspiciousFile.txt.Encrypted
[...]
Hello!

The flag is:

R$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flare-on.com
```

## Challenge 10 - Nur geträumt

### Description

```md
This challenge is a Macintosh disk image (Disk Copy 4.2 format, for those who need to know) containing a 68K Macintosh program. You must determine the passphrase used to decode the flag contained within the application. Super ResEdit, an augmented version of Apple's ResEdit resource editor which adds a disassembler, is also included on the disk image to help you complete the challenge, though you will likely also need to do some outside research to guess the passphrase. 

This application can be run on any Macintosh emulator (or any real Macintosh from as far back as a Mac Plus running System 6.0.x up to a G5 running Classic). The setup of the emulation environment is part of the challenge, so few spoilers live here, but if you want to save yourself some headaches, Mini vMac is a pretty good choice that doesn't take much effort to get up and running compared to some other options. 

This application was written on a Power Macintosh 7300 using CodeWarrior Pro 5, ResEdit, and Resourcerer (my old setup from roughly 1997, still alive!). It was tested on a great many machines and emulators, and validated to run well on Mac OS from 6.0.8 through 10.4. 

Happy solving! Be curious!
```

As mentioned in the description, this challenge is a Apple DiskCopy image. A `README.txt`  is also provided but it is only a copy of the challenge description above.

```bash
$ file Nur\ geträumt.img
Nur geträumt.img: Apple DiskCopy 4.2 image Nur getr\212umt, 1474560 bytes, MFM CAV dshd (1440k), 0x2 format
```

### Mounting the image

As this is a disk image, the first thing I did was mounting it. For that purpose, I used a tool named [Convert2Dsk](https://github.com/jonthysell/Convert2Dsk) that converts DiskCopy 4.2 images into raw disk images (HFS image in my case). Then, I used the [hfsutils](https://linux.die.net/man/1/hfsutils) tools to interact with the HFS image.

```bash
$ file Nur\ geträumt.img.dsk
Nur geträumt.img.dsk: Macintosh HFS data block size: 512, number of blocks: 2874, volume name: Nur getr\212umt
$ hmount Nur\ geträumt.img.dsk
Volume name is "Nur getrumt"
Volume was created on Fri Jul 29 10:54:35 2022
Volume was last modified on Wed Oct 19 22:05:58 2022
Volume has 522240 bytes free
$ hls
Desktop Folder       Nur getr?umt         Super ResEdit 2.1.3
```

The `hcopy` tool can be used to extract the application to analyze.
```bash
$ hcopy "Nur getr?umt" . 
$ file Nur_getr\X8aumt.bin
Nur_getrumt.bin: MacBinary II, inited, Sun Jan 16 03:32:01 2022, modified Thu Sep 15 18:10:54 2022, creator 'Nena', type application "Nur getr\212umt", at 0x80 6420 bytes resource  Apple HFS/HFS+ resource fork
```

### Analysis of the application

#### Static analysis

According to the specification of [MacBinary II](http://files.stairways.com/other/macbinaryii-standard-info.txt), the format is composed of a 128 bytes header followed by forks. In our case, there is only a resource fork corresponding to the 68k program we have to analyze. We can extract it using the following command line.
```
$ dd if=Nur_getr\X8aumt.bin of=resource.bin bs=1 skip=128 count=6420
```

Once we have the resource, we can load it and disassemble it in IDA using the IDC scripts from this [project](https://github.com/MacPaw/XADMaster/wiki/Disassembling68KMacExecutables).

Interestingly, the name of the creator indicated in the binary header (`Nena`) and the hardcoded string (`99 Luftballons`) seem to be a reference to a song named [99 Luftballons](https://en.wikipedia.org/wiki/99_Luftballons) from the German band Nena. 

We can identify the `main()` function of the program at the offset `0x13C0` and start to analyze it. I quickly spotted a XOR loop (in the `decodeFlag()` function) that seems to decrypt the flag from an encrypted data resource but I had some difficulties to retrieve the XOR key.

#### Dynamic analysis

At this point, I switched to dynamic analysis to get a better understanding of what the application actually does.

As mentioned in the challenge description, we can use Mini vMac to setup an emulation environment.

{{< figure src="/images/flareon9/Challenge_10_mini_vmac.png" >}}

Double-clicking on the application opens the following dialog.

{{< figure src="/images/flareon9/Challenge_10_ask_password.png" >}}

If we enter a dummy password, the flag value is modified accordingly.

{{< figure src="/images/flareon9/Challenge_10_test_password.png" >}}

This test indicates us that the password is the XOR key as XORing the input with the resulting flag returns the encrypted flag resource.

### Getting the flag

As we partially know what the flag looks like (ends with `@flare-on.com`), we can partially retrieve the XOR key. Indeed, if we XOR the end of the encrypted flag resource with `@flare-on.com`, we get `du etwas Zei` which looks like german words.

My skills in german are near zero, however searching for these words on Google and linking this with the previous hint we had on the song from the german band Nena, allowed me to identify the same words in the lyrics of this song: "Hast du etwas Zeit für mich?".

Using this sentence as the XOR key gives us the flag `Dann_singe_ich_ein_Lied_fur_dich@flare-on.com`.

## Challenge 11 - The challenge that shall not be named.

### Description

```md
Protection, Obfuscation, Restrictions... Oh my!!

The good part about this one is that if you fail to solve it I don't need to ship you a prize.
```

The last challenge is a Python application bundled in a PE executable using PyInstaller.
```bash
$ file 11.exe
11.exe: PE32+ executable (console) x86-64, for MS Windows
```

### First look

I used [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) to extract the Python scripts.

Two extracted files are particularly interesting:
- `11.pyc` is the compiled Python script we have to analyze;
- `pytransform.pyd` is a module that is part of the [PyArmor](https://pyarmor.dashingsoft.com/) obfuscator.

After using [uncompyle6](https://github.com/rocky/python-uncompyle6) to decompile `11.pyc`, we get the following Python script.
```python
from pytransform import pyarmor
pyarmor(__name__, __file__, b'PYARMOR\x00\x00\x03\x07\x00B\r\r\n\t0\xe0\x02\x01\x00\x00\x00\x01\x00\x00\x00@\x00\x00\x00a\x02\x00\x00\x0b\x00\x00x\xa7\xf5\x80\x15\x8c\x1f\x90\xbb\x16Xu\x86\x9d\xbb\xbd\x8d\x00\x00\x00\x00\x00\x00\x00\x0054$\xf1\xeb,\nY\xa9\x9b\xa5\xb3\xba\xdc\xd97\xba\x13\x0b\x89 \xd2\x14\xa7\xccH0\x9b)\xd4\x0f\xfb\xe4`\xbd\xcf\xa28\xfc\xf1\x08\x87w\x1a\xfb%+\xc1\xbe\x8b\xc0]8h\x1f\x88\xa6CB>*\xdd\xf6\xec\xf5\xe30\xf9\x856\xfa\xd9P\xc8C\xc1\xbdm\xca&\x81\xa9\xfb\x07HE\x1b\x00\x9e\x00a\x0c\xf2\xd0\x87\x0c<\xf8\xddZf\xf1,\x84\xce\r\x14*s\x11\x82\x88\x8d\xa7\x00k\xd9s\xae\xd3\xfc\x16v\x0f\xb9\xd1\xd3\xd02\xecQ\x9a\xd7aL\xdf\xc1~u\xca\x8a\xd4xk\xde\x030;\xb2Q\xc8$\xddQ\xd3Jj\xd1U\xccV\xd1\x03\xa9\xbf\x9f\xed\xe68n\xac&\xd67\x0c\xfd\xc6^\x0e\xb40\x07\x97|\xab\xadBc<T\x0b d$\x94\xf9\x90Oq\x027\xe4\xf2\xec\xc9\xbc\xfaL7dN\x83\x96X\xab\xf7\x18\xad\xfc\xf7\x992\x87\x1d\xe8p\x97C\xd4D.\x1b;F_ \x91t\tM\x155\x0c\xb9\x9f\xd0W C\x19oz4.\x998\xe7\xa9\x98\xd4\xd2\x9f\x95H\x91\xf2`\x1c\xfa\xa4,\xa9d?day\xc4\xf3\xcb\xc8r\xf7\x97\xd1u\xfe\xec\x91\xc1\xe6V\xa3j\x0f\xb9\xd5\xa1a\xd5\x17\x8b!\xc4{A\xb2t\x85\xfe\x88\xffaO\x05\xc5\xacg\xed;]\xb9\xdd\x7fS\xef\xe4F\xf9"\x0c\xd9\x1a\xb6\x88-Y \xdd\xea\xc9\xf1>:\xbf][\xdf[\x07\xb9\xe2@\xeeq\xf9Ho\xc3\xc4sD\xcd\xcc\x8a\x11tq\xf6;\xe9\x84\x7fb\xe9\xf4t\x80\xe4l)_\xeaQ\x10\x8f^-\xc5\x11\xe7\x84x\xe7-\xb2\x15[5\xb0\xdck\x1awh\r;\x9by\x14\x1a\xe0:\xbd\x904\xa2\xfap[\xe0\x9fn3\x7fk;3n\xf8\xe3%\xc6t\xbf|\x12\x9a\x1b\xe2\xf1C\x10\xbe\xee\xe7.\x98>k\xb9r\xf9\x9cN8\xae\xc0\x8bA\x0f\xbb\x8d\xf4\x04\xb0\x01,\x05\xaa\xc5\r\xce\x91\'\x98\xc6\xd3Y\x1b\xd1U\xd3\xd7d|{I\x18JG\xa63\xd6\'r\xcf!7\x17qd\xb7|\x1f\x7f\x17\xb4\xa8\xb9\xa8\xdaz\x02g\xc7+]F\x10\x18l\x0c\x91g\xd0e\x1f\xe4\xa67\xb2\xba\x9f\xef\xba\xc7[3_\x12C\xe9\xf4s\x87q\xa3\xec\xa0\xcc\x06\xf4\x9f\xe1\xb3\xe6R\x93\xf2\xd57i\xf8\x96\xb3x\xa7uEw\x12D\x8c\xc6XkdfY\xe0J2N\xbf\x85o\x8e\x81|C\xa91#y\xd9u\xf1\xd1BC\xcc}\xe8;?\x12S\x16', 2)
```

### Analyzing the PyArmor protection

#### Reading the documentation

Before this challenge, I was not familiar with PyArmor, so the first thing I did was looking for documentation on that obfuscator. Surprisingly, the official [documentation](https://pyarmor.readthedocs.io/en/latest/index.html) of the project is quite complete.

The following picture, taken from PyArmor official website, illustrates how the obfuscator works.

{{< figure src="/images/flareon9/Challenge_11_pyamor_big_picture.png" >}}

Obfuscated [code objects](https://docs.python.org/3/c-api/code.html) are wrapped between a header (`__armor_enter__`) and a footer (`__armor_exit__`). The former is responsible for restoring the original bytecode and the latter obfuscate the bytecode again after its execution.

PyArmor supports differents modes (Super Mode, Super Plus Mode, VM Mode, etc.) for obfuscating scripts. In our case, as there is no [Bootstrap code](https://pyarmor.readthedocs.io/en/latest/understand-obfuscated-scripts.html#bootstrap-code) at the beginning of the script, we can assert that at least the [Super Mode](https://pyarmor.readthedocs.io/en/latest/mode.html#super-mode) was used. Besides the fourth parameter given to the `pyarmor()` function means that the [obfuscating module mode](https://pyarmor.readthedocs.io/en/latest/mode.html#obfuscating-module-mode) was set to 2 (stronger cryptography algorithm).

At this point, I switched to the analysis of the pytransform module in order to understand how the code object was obfuscated.

#### Static analysis of the pytransform module

After loading the module in IDA, we can see there are only a few export functions. I started with `PyInit_pytransform()` as this is the function called when the module is imported in the Python script.

The function creates a new callable PyObject named `__armor_wrap__` using `PyCFunction_NewEx()`. Then, it initializes several ciphers, installs some anti-debug mechanisms (at `0x6D654420`) and verifies the PyArmor license.

What is interesting here is the `__armor_wrap__` function (handled at `0x6D604BC0`). Indeed, instead of using the functions `__armor_enter__` and `__armor_exit__`, it seems that the mode used to obfuscate this script calls `__armor_wrap__`. At the time of the challenge, the latter was not really documented so I continued my analysis on this function.

The bytecode is decrypted using AES-256 in CTR mode and executed by a (very) big function at `0x6D67A640` (see the CFG below).

{{< figure src="/images/flareon9/Challenge_11_exec_bytecode_cfg.png" >}}

From here, there are likely several solutions to continue this challenge but I chose the lazy one: using a debugger and breaking before the execution of the bytecode to extract it.

### Deobfuscating the Python script

In order to debug the script, there are two requirements:
- patching the anti-debug mechanisms (`NOP` is your friend);
- bypassing the [Restrict Mode](https://pyarmor.readthedocs.io/en/latest/mode.html#restrict-mode).

I discovered the latter when I was trying to attach my debugger to the Python process. As the mode 2 was used, I could not import the obfuscated script from a plain script without a "protection exception" being raised. However, this security measure can be patched as well.

Once these requirements are met, it is trivial to break before the bytecode execution and dump the decrypted code object.

{{< figure src="/images/flareon9/Challenge_11_partial_dump.png" >}}

As the flag was only a constant of the code object, the challenge was already over, but I still wanted to get a clean decompiled code. However, when I understood that the opcodes were remapped in the pytransform module, I changed my mind :)
