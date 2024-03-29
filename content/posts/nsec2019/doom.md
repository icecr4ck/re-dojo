---
authors: 
  - scud
title: NorthSec 2019 - Doom
date: 2019-05-22
tags:
  - Challenge
  - NorthSec
---

We, once again, participated in the NorthSec competition.
This article is about the DOOM challenge which was pretty interesting as you had to validate it at the VR station.
@actgardner already made a write-up that you can find [here](http://www.agardner.me/securit/ctf/northsec/2019/2019/05/19/northsec-ctf-part-1-doom.html).
I wanted to complete it and show another solution that icecr4ck and I came up with.

<!--more-->

{{< toc >}}

## Tearing the game apart

In order to navigate through the map I used **GZDoom builder** and loaded the **zoombies.wad** file. You can use the 'add resource' menu and select the folder containing all the other files from the game. This will show you the textures also.

![Image](/images/doom/GZbuilder_first_room.png "GZBuilder")

Just by browsing the map, you can find a flag in a closed room.

![Image](/images/doom/qr_code_flag.png "Hidden QR code")

Looking at the attributes of this door, you can see an action "When player presses use" and this action is linked to a script numbered 42.
After wandering the map, one can see that there are more scripted locked doors and also hidden rooms.
**SLADE** is a tool which lets you browse the different files and more importantly it can export the "BEHAVIOR.LMP" contained in the .wad file.
This file is a compiled script for doom. Then with **listacs** script you can disassemble or decompile the script (but be careful I had some wrong output with the decompilation the first time. I didn't use the latest version).

Remember the locked door with the QR code behind it? The script number 42 is the following code:

![Image](/images/doom/storage_room.png "Storage room script")

This door was never meant to be opened.

## Collecting the different flags

### Elevator (1 point)

The first flag you can obtain is by unlocking the elevator.
The elevator's script just checks if you press "4" and "2" on the the switches.

![Image](/images/doom/Elevator.png "Elevator script")

This first step would give you 1 point.

### Blue card

If you noticed the hidden toxic room, that's where the blue card awaits you.
But there's a trick...
As you can see on the picture, the highlighted edge is linked to a script but also as soon as you enter the room another script is activated.

![Image](/images/doom/Toxic_room.png "Toxic room script")

Once you pass the "hidden door" the script numbered 31 is executed and that's where a logic bug resides.

![Image](/images/doom/logic_bug.png "Logic bug")

The script does a modulo 256 on the player's health and then decreases this value randomly until it is below 20.
The script by the blue card (numbered 32) decreases the player's health by 200.

![Image](/images/doom/bluecard_script.png "Blue card script")

The trick here is to go to the other hidden room.

![Image](/images/doom/hidden_room.png "Hidden room")

This room contains a potion of 300 health points. The trick here is to have the health between 256 and 266 so that you don't lose health when you enter the room and then when getting the blue card you can lose 200 health points and still survive.

### Red card

The red card can be obtained after unlocking a specific door. The scripts responsible for its opening are number 21 and 22. They both call the function func4.
This function calls func6 which is collecting the different number or letters from the 6 switches and convert it to a base-10 number.
All the different digits composing that number are put in an array.
The verification code at the end of func4 can be converted to the following python code:

![Image](/images/doom/pseudocode.png "Python code")

The code is pretty straightforward and actually pretty simple to translate it to an equation to give it to z3 (SMT solver).
The following script will output the expected combination.

```python
from z3 import *
from numpy import base_repr

cmb = [2, 3, 5, 7, 13, 17, 19, 23, 31, 27]

solver = Solver()
digits = [Int("c_%d" % i) for i in range(10)]
 
for i in range(10):
    solver.add(digits[i] >= 0, digits[i] < 10)
    solver.add(((digits[i] * 100) + (digits[(i+1)%10] * 10) + digits[(i+2)%10]) % cmb[i] == 0)
    solver.add(((digits[i] * 100) + (digits[(i+1)%10] * 10) + digits[(i+2)%10]) != 0)

solution = ''
if solver.check() == z3.sat:
    model = solver.model()
    for i in range(10):
        solution += model[digits[i]].as_string()
print base_repr(int(solution),36)
```

Note that z3 takes a little less than 1 minute (at least on this old arse laptop).

## Conclusion

The challenge was very funny. I would not recommend doing VR if you only slept 8 hours during the whole weekend drinking Sabotage though...
