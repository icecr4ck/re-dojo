---
authors:
  - icecr4ck
title: Flare-On 9 solutions (part 1)
date: 2022-11-13
tags:
  - Challenge
  - Flare-On
---

This year, I participated in the [Flare-On](https://flare-on9.ctfd.io/) challenge organized by the FLARE team from ~~Mandiant~~ Google. 

In total, 11 challenges of reverse engineering with increasing difficulty were to be solved. I did managed to resolve them all and as there was not a lot of activity on this blog recently, I pushed myself to put together some write-ups.

<!--more-->

{{< figure src="/images/flareon9/flareon9_solves.png" >}}

I want to thank all the challenge authors, especially the one who made the eighth challenge as it was reallly the hardest but also the one that I learned the most from.

As my write-ups are a bit long, I split them in different blog posts. This is the part 1 that details the solutions of the challenges 1 to 4.

{{< toc >}}

Here are the links to the other solutions:
- [part 2](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-2/) for challenges 5 to 7;
- [part 3](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-3/) for challenge 8;
- [part 4](https://re-dojo.github.io/post/2022-11-13-FlareOn-9-part-4/) for challenges 9 to 11.

## Challenge 1 - Flaredle

### Description

```md
Welcome to Flare-On 9!

You probably won't win. Maybe you're like us and spent the year playing Wordle. We made our own version that is too hard to beat without cheating.

Play it live at: [http://flare-on.com/flaredle/](http://flare-on.com/flaredle/)
```

The first challenge is a Wordle-like game, developed using HTML and JavaScript.

{{< figure src="/images/flareon9/Challenge_1_flaredle.png" >}}

### Solution

If we look at the `script.js` file (corresponding to the game logic), we see the right guess is defined at the beginning of the script.
```js
import { WORDS } from "./words.js";

const NUMBER_OF_GUESSES = 6;
const WORD_LENGTH = 21;
const CORRECT_GUESS = 57;
let guessesRemaining = NUMBER_OF_GUESSES;
let currentGuess = [];
let nextLetter = 0;
let rightGuessString = WORDS[CORRECT_GUESS];
[...]
```

By resolving the word in `words.js`, we get `flareonisallaboutcats`, which immediately gives the flag.

{{< figure src="/images/flareon9/Challenge_1_flaredle_solved.png" >}}

## Challenge 2 - Pixel Poker

### Description

```md
I said you wouldn't win that last one. I lied. The last challenge was basically a captcha. Now the real work begins. 
Shall we play another game?
```

For this challenge, we have a PE executable to analyze.
```bash
$ file PixelPoker.exe 
PixelPoker.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

### Solution

When executed, a picture is showed and we have to click on a specific pixel to get the flag. If we miss more than 10 times, a popup is displayed.

{{< figure src="/images/flareon9/Challenge_2_pixelpoker.png" >}}

After opening the executable in IDA, we can easily retrieve the function responsible for creating the window (at `0x401120`) and the associated callback (at `0x4012c0`).

When the user clicks on a pixel, the callback checks the x and y coordinates of the pixel against the result of a modulo operation on hardcoded values. Here is a Python implementation of the check.
```python
import struct

s = b"FLARE-On"

assert x == struct.unpack("I", s[:4])[0] % 0x2e5 # 95
assert y == struct.unpack("I", s[4:])[0] % 0x281 # 313
```

Clicking on the pixel at `(95, 313)` gives the flag.

{{< figure src="/images/flareon9/Challenge_2_pixelpoker_solved.png" >}}

## Challenge 3 - Magic 8 Ball

### Description

```md
You got a question? Ask the 8 ball!
```

The third challenge is a PE executable dynamically linked with several DLLs, including the SDL (generally used to develop computer games).
```bash
$ file Magic8Ball.exe
Magic8Ball.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

### Solution

When executed, the program waits for a combination of arrow keys and a question.

{{< figure src="/images/flareon9/Challenge_3_magic8ball.png" >}}

After opening the executable in IDA, we can identify the function at `0x2924E0` as the one checking the user input. 

By statically analyzing this function, we retrieve the combination of arrow keys (`LLURULDUL`) to ask the question that gives us the flag (`gimme flag pls?`). Note that the question is set by the function at `0x292090`. 

{{< figure src="/images/flareon9/Challenge_3_magic8ball_solved.png" >}}

## Challenge 4 - darn_mice

### Description

```md
"If it crashes its user error." -Flare Team
```

This challenge is a PE executable that waits for a specific command line parameter.
```bash
$ file darn_mice.exe
darn_mice.exe: PE32 executable (console) Intel 80386, for MS Windows
```

### Solution

When executed with a dummy input, we get the following output.
```powershell
> .\darn_mice.exe AAAAAAAAAAAAAAAAAAAAAAA
On your plate, you see four olives.
You leave the room, and a mouse EATS one!
```

By doing static analysis, we can see that the user input is used as a key to decrypt the flag. 

Also, the input has to verify several conditions:
- input length is equal to 35 bytes;
- input is printable;
- when adding a byte of the input to a byte of a hardcoded sequence, we get an executable function which is immediately called (see screenshot of the corresponding decompiled code below).

{{< figure src="/images/flareon9/Challenge_4_darn_mice.png" >}}

The last condition is the most important one as there is only one possibility to respect it: the called instruction has to be a `ret`. Meaning that the sum of each input byte and a byte of the hardcoded sequence has to be equal to `0xc3`.

From there, it is trivial to get the user input using a few lines of Python.
```python
hardcoded_seq = bytes.fromhex("505E5EA34F5B515E5E97A38090A38090A38090A38090A38090A38090A38090A2A36B7F")

ret = 0xc3
user_input = []
for i in range(len(hardcoded_seq)):
    user_input.append(ret - hardcoded_seq[i])

print(bytes(user_input).decode())
```

This script gives the encryption key `see three, C3 C3 C3 C3 C3 C3 C3! XD` and the latter gives us the flag.

```powershell
> .\darn_mice.exe "see three, C3 C3 C3 C3 C3 C3 C3! XD"
On your plate, you see four olives.
You leave the room, and a mouse EATS one!
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
When you return, you only: see three, C3 C3 C3 C3 C3 C3 C3! XD
i_w0uld_l1k3_to_RETurn_this_joke@flare-on.com
```
