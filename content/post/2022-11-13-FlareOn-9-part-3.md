---
authors:
  - icecr4ck
title: Flare-On 9 solutions (part 3)
date: 2022-11-13
tags:
  - Challenge
  - Flare-On
---

This blog post details the solution of the challenge 8 of the Flare-On 9.

<!--more-->

{{< toc >}}

Here are the links to the other solutions:
- [part 1](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-1/) for challenges 1 to 4;
- [part 2](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-2/) for challenges 5 to 7;
- [part 4](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-4/) for challenges 9 to 11.

## Challenge 8 - backdoor

### Description

```Plain
I'm such a backdoor, decompile me why don't you...
```

The eighth challenge is a PE executable written in .NET.
```bash
$ file FlareOn.Backdoor.exe
FlareOn.Backdoor.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

### First look

When the executable is opened in dnSpy, we quickly understand that something is wrong as some methods cannot be decompiled.

{{< figure src="/images/flareon9/Challenge_8_main_function.png" >}}

Looking more closely at the other functions of the executable, we can divide them into two categories.
- `flare_XX()`: classic C# bytecode, can be decompiled using dnSpy.
- `flared_XX()`: obfuscated/encrypted methods.

{{< figure src="/images/flareon9/Challenge_8_function_list.png" >}}

### Understanding the first layer of obfuscation

If we follow the execution flow from the `Main()` function, the function `FLARE15.flare_74()` is called to initialize several global arrays and returns normally. Then, the call to `Program.flared_38()` raises an exception (`InvalidProgramException`) as the method is invalid. The exception is catched and leads to the execution of `FLARE15.flare_70()`.

{{< figure src="/images/flareon9/Challenge_8_flare_70.png" >}}

Again, an exception is raised when `FLARE15.flared_70()` is executed and this time it is handled by `FLARE15.flare_71()`. Interestingly, the latter also takes two extra parameters: `FLARE15.wl_m` and `FLARE15.wl_b` (defined in `FLARE15.flare_74()`).

This method is not obfuscated and can be easily analyzed once decompiled. Here is what it does.
1. Retrieve the [metadata token](https://learn.microsoft.com/en-us/dotnet/standard/metadata-and-self-describing-components#metadata-tokens) of the function that caused the exception from the stack trace.
2. Get the prototype of the function from the metadata token.
3. Create a new `DynamicMethod` from the prototype.
4. Iterate over the `Dictionary` given as third parameter (`FLARE15.wl_m`)
	- each key is an index in the byte array given as fourth parameter (`FLARE15.wl_b`), the latter is actually the bytecode of the dynamic method previously created;
	- each value is a valid metadata token in the program.
5. Each metadata token is translated into a valid token in the scope of the dynamic method. For example, if the token "points" to a string of the program, it is first resolved via `Module.ResolveString()` and then a token is created using `DynamicILInfo.GetTokenFor()`.

{{< figure src="/images/flareon9/Challenge_8_flare_71_resolve_token.png" >}}

6. The resulting token is written to the bytecode of the dynamic method at the index specified by the `key` variable.

{{< figure src="/images/flareon9/Challenge_8_flare_71_patch_token.png" >}}

7. Finally, the patched bytecode is set as the code body of the dynamic method and the latter is executed.

{{< figure src="/images/flareon9/Challenge_8_flare_71_exec_bytecode.png" >}}

In a nutshell, this method patches the bytecode given as parameter using the provided metadata tokens and invokes it as a dynamic method.

Using the "Analyzer" feature (accessible by right-clicking on method name) of dnSpy, we can identify the locations where `FLARE15.flare_71()` is called, and thus, the methods obfuscated via this technique.

{{< figure src="/images/flareon9/Challenge_8_flare_71_cross_refs.png" >}}

For each method, the actual bytecode and the metadata tokens can be retrieved from the parameters given to `FLARE15.flare_71()`.

### Recovering the first layer methods

From there, I chose to statically fix the obfuscated methods by the actual executed bytecode, in order to get the decompiled code when the patched executable is loaded into dnSpy.

This is actually quite trivial, just follow the steps below for each obfuscated method.
1. Retrieve the real bytecode (i.e `cl_b`) and the corresponding metadata tokens (i.e `cl_m`).
2. Iterate over each `key`/`value` of the metadata tokens dictionary, and patch the bytecode at index `key` with the metadata token `value`.
3. Write the resulting bytecode over the obfuscated method in the executable. 

This can be done in a few lines of Python, my script is available on [GitHub](https://github.com/icecr4ck/write-ups/blob/master/FlareOn-9/Challenge_8_backdoor/patch_first_layer.py).

### Understanding the second layer of obfuscation

Obviously, this was only a first step as lots of methods remain obfuscated/encrypted (including `Program.flared_38()`), but we can now statically analyze `FLARE15.flared_70()` (called when `Program.flared_38()` raises an exception).

{{< figure src="/images/flareon9/Challenge_8_flared_70.png" >}}

In a nutshell, it decrypts and executes the method that caused the exception. The different steps of this process are detailed below.
1. Get metadata token of the method that raised the exception.
2. `FLARE15.flared_66()` computes a SHA256 hash of some of the attributes (return type, prototype, etc.) of the method resolved by the token.
3. `FLARE15.flared_69()` gets the contents of the section whose name starts with the first four bytes (in hexadecimal) of the SHA256 hash previously computed.
4. `FLARE15.flared_46()` decrypts (RC4) the section contents using the key given as parameter (`1278abdf` in hexa), the decrypted data corresponds to the actual bytecode of the method.
5. `FLARE15.flared_67()` decrypts the metadata tokens of the bytecode (XOR with `0xa298a6bd`) and executes it as a dynamic method (using similar code to `flare_71()`).

This technique is used to protect all the remaining obfuscated methods of the executable.

### Recovering the second layer methods

Again, I chose to decrypt the obfuscated methods statically.

This time, the algorithm is a bit more complex as `FLARE15.flared_67()` uses a large hardcoded dictionary to identify the offsets of the bytecode to patch. The most painful part of this step was probably to retrieve the relation between a section name (containing the encrypted bytecode) and the offset of the obfuscated method in the executable.

The Python script I used to patch the second layer of obfuscation is available on [GitHub](https://github.com/icecr4ck/write-ups/blob/master/FlareOn-9/Challenge_8_backdoor/patch_second_layer.py).

### Analyzing the backdoor

Once the obfuscation is defeated, we can finally analyze the actual code of the backdoor, starting with the `Program.flared_38()` method.

#### Initialization

After creating a `Mutex` (set to `e94901cd-77d9-44ca-9e5a-125190bcf317`), the method initializes several variables in the `FLARE13` module before entering a while loop where the control flow seems to have been flattened.

{{< figure src="/images/flareon9/Challenge_8_flared_38_cff.png" >}}

The `FLARE13.flare_50()` is responsible to update the `FLARE13.cs` variable which indicates the next method to call. The latter depends on the return value of the method given as parameter as well as on a dictionary (`FLARE13.t`) initialized by `FLARE13.flare_48()`.

Before entering the while loop, a file named `flare.agent.id` is created in the same directory as the backdoor. It contains an `agent_id` (set to `-` by default) and a `counter` (set to a random value between 0 and 46656). We will return on these two variables in the next sections.

The first case to be executed is `FLARE08.A` but it does not call any method, which only sets the next case to `FLARE08.C` (as shown on the screenshot below). The latter initializes a communication channel with the Command and Control server.

{{< figure src="/images/flareon9/Challenge_8_flared_48.png" >}}

#### Communication protocol

The backdoor communicates with its Command & Control (C&C) server via DNS (only A queries are supported).

Obviously, the domain name of the C&C server is `flare-on.com`. The payload is encoded using a custom algorithm as a sub-domain.

The method responsible for building the payload is `FLARE05.flared_29()`. It takes two parameters:
- a payload type (`FLARE06.DomT`));
- a string.

Five different payload types are implemented by the backdoor, they are detailed in the following table. 

| Payload type   | Description                       |
| -------------- | --------------------------------- |
| FLARE06.DomT.A | Initialize communication with C&C |
| FLARE06.DomT.B | Send result data                  |
| FLARE06.DomT.C | Ask for task data                 |
| FLARE06.DomT.D | Ask for next task                 | 
| FLARE06.DomT.E | Ask for task                      |

The following sequence diagram sums up how the different payloads are used by the backdoor.

{{<mermaid>}}
sequenceDiagram
	participant Backdoor
	participant C2
	Backdoor->>C2: DomT.A (HELLO)
	C2->>Backdoor: Answer (NEW AGENT_ID)
	Backdoor->>C2: DomT.E (REQUEST TASK)
	C2->>Backdoor: Answer (TASK SIZE)
	loop GET_TASK_DATA
		Backdoor->>C2: DomT.C (REQUEST TASK DATA)
		C2->>Backdoor: Answer (TASK DATA)
	end
	loop SEND_TASK_RESULT
		Backdoor->>C2: DomT.B (TASK RESULT DATA)
		C2->>Backdoor: Answer (NEXT TASK SIZE)
	end
	Backdoor->>C2: DomT.D (REQUEST NEXT TASK DATA)
	C2->>Backdoor: Answer (TASK DATA)
{{</mermaid>}}

Payload data is encoded using a substitution alphabet built from the `counter`. More precisely, the alphabet is randomly generated using a [Mersenne-Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) seeded with the `counter`. The latter is incremented by one after each request to the C&C server.

As the value of the `counter` is also randomly generated, it is encoded using another substitution alphabet (hardcoded this time) and sent to the C&C server.

#### Command execution

Once the backdoor has finished to received task data, it calls the method `FLARE07.flared_56()` to process the task.

The first byte of task data corresponds to the task type (defined in `FLARE06.TT`). Depending on the latter, the rest of the task data can be decompressed before being interpreted.

| Type           | Is compressed | Description                       |
| -------------- | ------------- | --------------------------------- |
| `FLARE06.TT.A` | N/A           | Not implemented                   |
| `FLARE06.TT.B` | Yes           | Execute a command                 |
| `FLARE06.TT.C` | No            | Execute a command                 | 
| `FLARE06.TT.D` | No            | Write `:)` to the given file path |
| `FLARE06.TT.E` | Yes           | Write `:)` to the given file path |

Various commands are supported by the backdoor, and most of them are base64-encoded.

{{< figure src="/images/flareon9/Challenge_8_command_example.png" >}}

Once decoded, the command shown on the screenshot above corresponds to:
```powershell
$(ping -n 1 10.65.45.3 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.4.52 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.31.155 | findstr /i ttl) -eq $null;$(ping -n 1 flare-on.com | findstr /i ttl) -eq $null
```

Interestingly, most of the commands append a short string to a global variable (`FLARE14.h`) when they are executed. Two other methods also use this global variable.
- `FLARE11.flared_42()` initializes the Mersenne-Twister algorithm but also the variable `FLARE14.h` as an `IncrementalHash` object (only once). `IncrementalHash` provides support for computing hashes incrementally across several segments. In our case segments are the short strings appended by the commands of the backdoor.

{{< figure src="/images/flareon9/Challenge_8_flared_42.png" >}}

- `FLARE14.flared_54()` reverses `FLARE14.sh` to obtain a section name, computes the hash to get a RC4 key and uses it to decrypt the section data. Then it decrypts the hash with a hardcoded RC4 key to get a filename, and writes the decrypted section data to this file. Finally, the latter is executed/started as a new process.

{{< figure src="/images/flareon9/Challenge_8_flared_54.png" >}}

### Decrypting the final stage

At this point, we understand that we have to execute commands in a particular order by the backdoor to decrypt and execute the next (and maybe final) stage.

To determine the order in which the commands have to be executed, we need to understand how `FLARE14.sh` is built. The method responsible for updating this variable is `flared_55()`.

{{< figure src="/images/flareon9/Challenge_8_flared_55.png" >}}

This method takes the command identifier and the short string corresponding to the command as parameters. It checks if the first item of `FLARE15.c` corresponds to the command identifier XORed with 248. If it is the case, the short string is appended to `FLARE14.sh` and the item that matched in `FLARE15.c` is removed. Thus this array gives us the order in which the commands have to be executed.

{{< figure src="/images/flareon9/Challenge_8_observable_collection.png" >}}

I chose to implement my own C&C server to execute the different commands. The code is available on [GitHub](https://github.com/icecr4ck/write-ups/blob/master/FlareOn-9/Challenge_8_backdoor/c2_server.py).

After executing all the commands, a GIF file is finally decrypted by the backdoor.

{{< figure src="/images/flareon9/Challenge_8_flag.gif" >}}
