---
title: Writeup - Tedious (UIUCTF 2021)
date: 2021-08-05 00:00:00
tags: 
- writeup
- rev
- uiuctf2021
---

# UIUCTF 2021 - Tedious Writeup
* Type - Reverse Engineering
* Name - Tedious
* Points - 50

## Description
```
Enter the flag and the program will tell you if it is correct!

author: Chief

[challenge]
```

## Writeup
Okay I'm going to be straight up and say - I suck at reverse engineering. I know this was a basic challenge, but it took me a hot second and I didn't even fully reverse it. So this was quite the train wreck, but this is what I did, and it worked!

The first thing I did with the challenge binary I downloaded was put it in Ghidra, navigate to the main function, and export the assembly into decompiled C code. This is how I got [manglePassword.c](/static/uiuctf-tedious/manglePassword.c). However, Ghidra isn't perfect at reverse engineering, so it still requires a lot of work going through the code and making it readable. I started going through the code, replacing `undefined4` with int, while loops with for loops, and so forth until I felt like I understood what the binary was doing. 

```
undefined8 main(void) {
  // initializations
  long lVar1;
  long local_10;
  local_10 = *(long *)(in_FS_OFFSET + 40);
  //etc... removed for readability


  // asks for the flag and puts it into input
  puts("Enter the flag:");
  fgets((char *)input,40,stdin);


  // it does a bunch of math to add and subtract integers 
  // from the character code of each letter inputted
  for (int i = 0; i < 39; i++) {
    input[i] += 0x3b ^ 0x38;//3
  }
  for (int i = 0; i < 39; i++) {
    input[i] += 0x12 ^ 0xfd;//239
  }
  // etc... other loops removed for readability


  // clears everything?
  puVar2 = &local_d8;
  for (int j = 20; j != 0; j--) {
    *puVar2 = 0;
    puVar2++;// = puVar2 + 1;//(bVar3 * -2) + 1;
  }


  // initializes array of values to compare it to
  local_d8._0_4_ = 0x4d;
  local_d8._4_4_ = 0xb9;
  local_d0 = 0x4d;
  local_cc = 0xb;
  local_c8 = 0xd4;
  // etc... other initializations removed for readability


  // tells you if you got it right or wrong
  for (int i = 0; i <= 38; i++) {
    if (i==38) {
      printf("GOOD JOB!");
    }
    else if (input[i] != local_d8 + (i*4)) {
      printf("WRONG!! ");
      break;
    }
  }
  return 0;
}
```

It was taking your 38-character input, doing a bunch of XORing numbers, and adding or subtracting it from the character code. It then compared it to an array of integer values and told you if you got it right or wrong. You can see how far I got in decompiling this code in manglePassword.c. I went through and (TEDIOUSLY) did all the math by hand, and found it adds 2010 to each character code. This obviously put the result way out of the ASCII range in hexadecimal, so I figured once it reached the max value for the data type, it went to the minimum value and started incrementing again. At this point, the manual conversion from hex to decimal and addition/subtraction had gotten to me and I was frustrated.

I decided to take a different approach - I figured that if I could fix the errors Ghidra gave me after converting the binary into C code, I could add my own print statements and have it give me the vital information. I then decompiled the binary in Ghidra into C, made some changes to take out errors, and added a print statement on line 241 (see [manglePassword2.c](/static/uiuctf-tedious/manglePassword2.c)) that printed out the decimal value for each character. I made [create_array.py](/static/uiuctf-tedious/create_array.py), which ran the binary inputting a single, unique character, and outputted the decimal value that the modified binary put out.

```
{'a': 81, 'b': 106, ..., '(': 80, ')': 121}
```

This array maps out each character to the value it has AFTER all the XORing and math and stuff, thereby removing the need for me to do the math manually (I wish I had thought of this earlier). I then created the [answer.py](/static/uiuctf-tedious/answer.py) file, which had the values above and an array with the flag.

```
array = {'a': 81, 'b': 106, ..., '(': 80, ')': 121}

answer = [77, 57, ..., 117, 18]

for letter in answer:
    for value in array:
        if array[value] == letter:
            print(value, end="")

print()
```

It simply loops through the values in the answer variable, then sees which letter it matches up with and prints it out. When you run answer.py, it prints out the flag!

**Flag:** `uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}`

## Real-World Application
As a beginner in reverse engineering, this challenge taught me a lot. First, I learned about the difference between static and dynamic analysis - what I attempted at the beginning was static analysis. I looked through the steps, and tried to copy it manually. Due to the tediousness of all the math, and dealing with variable types, it is possible but not desirable and it's easy to make a mistake. Dynamic analysis was much easier; I'm still learning about dynamic analysis, but having the program do all the work and just peeking in on the important stuff was much better. 

For anyone starting to get into reverse engineering, there's a lot to tackle! I recommend you spend time learning to do dynamic analysis because it can make the task of reverse engineering seem less intimidating. 