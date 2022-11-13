---
authors:
  - icecr4ck
title: Flare-On 9 solutions (part 2)
date: 2022-11-13
tags:
  - Challenge
  - Flare-On
---

This blog post details the solutions of the challenges 5 to 7 of the Flare-On 9.

<!--more-->

{{< toc >}}

Here are the links to the other solutions:
- [part 1](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-1/) for challenges 1 to 4;
- [part 3](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-3/) for challenge 8;
- [part 4](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-4/) for challenges 9 to 11.

## Challenge 5 - T8

### Description

```md
FLARE FACT #823: Studies show that C++ Reversers have fewer friends on average than normal people do. That's why you're here, reversing this, instead of with them, because they don't exist.

We’ve found an unknown executable on one of our hosts. The file has been there for a while, but our networking logs only show suspicious traffic on one day. Can you tell us what happened?
```

For this challenge, we get a PE executable and a PCAP capture.
```bash
$ file t8.exe traffic.pcapng
t8.exe:         PE32 executable (console) Intel 80386, for MS Windows
traffic.pcapng: pcapng capture file - version 1.0
```

### Solution

As mentioned in the description, the executable is a fake backdoor developed in C++.

Starting from the `main()` function, the backdoor performs the following actions.
1. Decrypts (one-byte XOR) the domain name of the Command and Control server (`flare-on.com`).
2. Instantiate a `CClientSock` object, this is a custom class responsible for communicating with the Command and Control server (via HTTP).
3. Set the HTTP request type of the object to `POST`.
4. Compute the MD5 hash of the `FO9` string concatenated with a random number, and use the resulting hash as a RC4 key.
5. Encrypt the payload (`ahoy`) using the previous RC4 key and encode the result using base64.
6. Append the random number used to build the RC4 key to the User-Agent of the request.
7. Send the request to the Command and Control server.
8. Decode (base64) and decrypt the response using the same RC4 key.
9. Parse and decode the decrypted response using a custom algorithm.
10. Compute the MD5 hash of the concatenation of the previous step result and `@flare-on.com` (which gives the flag basically), the resulting hash is used as a second RC4 key.
11. Encrypt the payload (`sce`) using this new RC4 key, encode the result using base64 and send the request to the Command and Control server.
12. Decode (base64) and decrypt (second key) the response.
14. The decrypted response corresponds to a shellcode, which is immediately mapped and executed.

The first goal was to retrieve the initial RC4 key. This requires to extract the random number appended to the User-Agent of the first request from the PCAP.

{{< figure src="/images/flareon9/Challenge_5_t8_user_agent.png" >}}

Retrieving the initial RC4 key can be done in a few lines of Python. Note that the strings are wide.
```python
import hashlib

to_wide = lambda x : x.encode("utf-16")[2:]

rand_num = 11950

m = hashlib.md5()
m.update(to_wide("FO9") + to_wide(str(rand_num)))
print(m.hexdigest()) # a5c6993299429aa7b900211d4a279848
```

Once we have the initial RC4 key, we can decode, decrypt and parse the response to the first request. 

As the algorithm used to decode the decrypted response was a bit painful to reverse (see code at `0x404570`), I used the Appcall feature of IDA to instrument the function. 
```python
import struct
import ida_idd
from base64 import b64decode
from Crypto.Cipher import ARC4

upck32 = lambda x : struct.unpack("I", x)[0]

rc4_key = "a5c6993299429aa7b900211d4a279848".encode('utf-16')[2:]
response = b"TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg=="

response_dec = ARC4.new(rc4_key).decrypt(b64decode(response))

flag = []
for chunk in response_dec.split(b",\x00"):
    dec_chunk = ida_idd.Appcall.decode_chunk(upck32(chunk[:4]), upck32(chunk[4:8]), upck32(chunk[8:12]), upck32(chunk[12:]))
    dec_char = ida_idd.Appcall.chunk_to_char(dec_chunk)
    flag.append(dec_char)
    
print(bytes(flag).decode() + "@flare-on.com")
```

The execution of this script in a debug session gives the flag `i_s33_you_m00n@flare-on.com`.

At this point, the challenge was already finished but I wanted to know what the shellcode does, so I decrypted it. 
```python
import hashlib
from base64 import b64decode
from Crypto.Cipher import ARC4

to_wide = lambda x : x.encode("utf-16")[2:]

m = hashlib.md5()
m.update(to_wide("i_s33_you_m00n@flare-on.com"))
rc4_key = to_wide(m.hexdigest())

response = b"F1KFlZbNGuKQxrTD/ORwudM8S8kKiL5F906YlR8TKd8XrKPeDYZ0HouiBamyQf9/Ns7u3C2UEMLoCA0B8EuZp1FpwnedVjPSdZFjkieYqWzKA7up+LYe9B4dmAUM2lYkmBSqPJYT6nEg27n3X656MMOxNIHt0HsOD0d+"

shellcode = ARC4.new(rc4_key).decrypt(b64decode(response))

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)
```

Turns out, the shellcode is not that interesting (call to `FatalAppExit(0, "You're a mac !!!\x00")`). Here is a commented version of the disassembled shellcode.

{{< figure src="/images/flareon9/Challenge_5_shellcode.png" >}}

## Challenge 6 - à la mode

### Description

```md
FLARE FACT #824: Disregard flare fact #823 if you are a .NET Reverser too.

We will now reward your fantastic effort with a small binary challenge. You've earned it kid!
```

For this challenge, we have a PE DLL written in .NET and a text file corresponding to a chat log with the incident response team. 
```bash
$ file HowDoesThisWork.dll IR\ chat\ log.txt
HowDoesThisWork.dll: PE32 executable (DLL) (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
IR chat log.txt:     ASCII text, with CRLF line terminators
```

Here are the contents of the `IR chat log.txt` file.
```md
[FLARE Team]  Hey IR Team, it looks like this sample has some other binary that might interact with it, do you have any other files that might be of help.

[IR Team]     Nope, sorry this is all we got from the client, let us know what you got.
```

### Solution

After opening the executable in dnSpy, one can notice that the entry point indicated by the dnSpy (`0x0000181A`) is a native entry point. This means this address does not point to managed code (.NET code) but to unmanaged code (x86 assembly in this case).

{{< figure src="/images/flareon9/Challenge_6_dnspy.png" >}}

At this point, I switched to IDA to continue the analysis. The code at `0x1000181A` corresponds to a classic DLL entry point, it is trivial to identify the `DllMain()` at `0x10001163`. The latter does two things:
- resolve several Windows API by parsing the module list from the PEB (the API names are encrypted with a one-byte XOR);
- start the main thread.

The main thread creates a named pipe `\\.\pipe\FlareOn` and read from it. If it receives the string `MyV0ic3!` then the flag is decryted (using RC4) and written on the pipe.

One thing to note is the reuse of the same RC4 stream to decrypt the string `MyV0ic3!` and the flag (see the script below).
```python
from Crypto.Cipher import ARC4

rc4_key = bytes.fromhex("558BEC83EC20EBFE")
cipher = ARC4.new(rc4_key)

passwd = cipher.decrypt(bytes.fromhex("3E3951FBA211F7B92C"))
flag = cipher.decrypt(bytes.fromhex("E160A118932E96AD73BB4A92DE180AAA4174ADC01D9F3F19FF2B02DBD1CD1A"))
print(flag.decode())
```

The resulting flag is `M1x3d_M0dE_4_l1f3@flare-on.com`.

Interestingly, the first 6 bytes of the RC4 key match a classic prologue of a x86 function.

## Challenge 7 - anode

### Description

```md
You've made it so far! I can't believe it! And so many people are ahead of you!
```

This challenge is a (very) large PE executable.
```
$ file anode.exe
anode.exe: PE32+ executable (console) x86-64, for MS Windows
$ ls -lh anode.exe
-rw-r--r--. 1 user user 55M Sep 26 14:08 anode.exe
```

Looking at the strings of the executable shows that this is actually a Node.js application built using [nexe](https://github.com/nexe/nexe).

### Extracting and analyzing the JS script

The first step consists to extract the embedded JS script. This can be done either using `strings` or the npm package [nexe-decompile](https://www.npmjs.com/package/nexe-decompile). By using one of these methods, we get a large [JS script](https://github.com/icecr4ck/write-ups/blob/master/FlareOn-9/Challenge_7_anode/anode.js).

When executed, the script asks for the flag (size is 44 bytes) and enters a large switch statement (1024 cases in total) where each case modifies a byte of the input by a combination of other bytes of the input. 
```javascript
case 306211:
	if (Math.random() < 0.5) {
		b[30] -= b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + Math.floor(Math.random() * 256);
		b[30] &= 0xFF;
	} else {
		b[26] -= b[24] + b[41] + b[13] + b[43] + b[6] + b[30] + 225;
		b[26] &= 0xFF;
	}
	state = 868071080;
	continue;
```

At the end of the switch statement, the modified input is checked against an hardcoded sequence.
```javascript
var target = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76];
if (b.every((x,i) => x === target[i])) {
	console.log('Congrats!');
} else {
	console.log('Try again.');
}
```

In addition to these large equations to solve, the `math` module of Node.js was tampered with:
- `if` statements that depends on integers only have a different behavior depending on the integer (see the example below);
```javascript
// something strange is happening...
if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
}
```
- `Math.random()` is not so random as two consecutive executions of the executable produce the same "random" numbers.

At this point, I had an idea on how I could solve this challenge but my solution required to know which modifications were done in the `math` module. 

### Dealing with the `math` module

My first attempt was to do static analysis of the module in IDA to understand the modifications. However, I quickly gave up this idea as there are way too many functions to look at, and I did not manage to identify the ones that could be of interest.

{{< figure src="/images/flareon9/Challenge_7_anode_functions.png" >}}

After that, I thought to compile the same version of Node.js using `nexe` and then do some binary diffing with the executable, but I was not sure to get good results.

Instead, I chose to modify a bit the embedded script to leak two things:
- the "random" numbers generated by `Math.random()`;
- the result of the `if` conditions present in the script.

For the former, I replaced some code at the beginning of the JS script with a `for` loop of 10000 iterations that prints (using `console.log()`) the result of `Math.random()` on `stdout` (redirected to a file named `math_random.txt`). 

For the latter, I extracted all the numbers present in `if` conditions in the script, and gave the list to the following script (via the `if_cond.txt` file).
```python
import subprocess

PATCH_OFFSET = 0x35e3874

with open("if_cond.txt", "r") as f:
    conditions = [line.strip() for line in f]

for cond in conditions:
    data_to_patch = b"  if (" + cond.encode() + b") {\n    console.log(1);\n  }\n\n\n\n\n\n\n"

    with open("anode_patched.exe", "rb") as f:
        data = bytearray(f.read())

    for i in range(len(data_to_patch)):
        data[PATCH_OFFSET+i] = data_to_patch[i]

    with open("anode_patched.exe", "wb") as f:
        f.write(data)

    proc = subprocess.Popen(['anode_patched.exe'], stdout=subprocess.PIPE)
    output = proc.stdout.read().strip().decode()

    if not output:
        output = "0"

    print("{}:{}".format(cond, output))
```

This Python script patches the JS script with a test on each extracted number, and executes the application (using the `subprocess` module). If it prints `1` then the number corresponds to a `True`, otherwise, to a `False`. Again, those results are written on the `stdout`, which is redirected to a file (named `if_cond_results.txt`).

### Extracting the equations

Once I had these two files (`math_random.txt` and `if_cond_results.txt`), the next step was to extract and parse the equations. 

Here is the algorithm I used for each case of the switch statement.
1. Compute the case number from the state value (requires the `math_random.txt`).
2. If the case number is `185078700` (case that breaks the `while` loop) then stop the algorithm.
3. Get the offset of the switch case in the JS script (using regex).
4. Identify and resolve the `if` statement (either a check on `Math.random()` or an integer) after the case (still using regex).
5. Depending on the taken branch, extract the corresponding equation (regex again).
6. If necessary, replace the call to `Math.random()` in the equation by the actual value.
7. Extract the next state value and go back to step 1.

Obviously, the algorithm starts with the initial state value used by the script (`1337`), so it follows the actual execution flow of the script (which is quite important to correcly solve the equations).

### Solving the equations

The last step consists to solve the resulting equations. I chose to use `z3`.

Before using the solver, I had to clean the equations a bit, espcially:
- differentiate the versions a one byte of the flag (as each byte is rewritten several times);
- replace the `=` symbol with  `==` ;
- add logical AND with `0xFF` because operations are done on bytes only.

Also, I had some specificities of `z3` to deal with:
- each version of a byte of the flag needs to be repesented by a `z3`  variable (a `BitVec` in my case);
- using `eval()` to add the equations (which are `str` objects) in the solver.

The final script is available on [GitHub](https://github.com/icecr4ck/write-ups/blob/master/FlareOn-9/Challenge_7_anode/solve.py).

```bash
$ time python solve.py
n0t_ju5t_A_j4vaSCriP7_ch4l1eng3@flare-on.com

________________________________________________________
Executed in    3.24 secs    fish           external
   usr time    3.07 secs  392.00 micros    3.07 secs
   sys time    0.15 secs  204.00 micros    0.15 secs
```
