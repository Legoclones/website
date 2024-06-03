---
title: Writeup - Everlasting_Message (Codegate Quals 2024)
date: 2024-06-01 00:00:00
tags: 
- writeup
- rev
- codegatequals2024
---

# Codegate Quals 2024 - Everlasting_Message
## Description
```markdown
This binary won't stop sending messages. It seems to be trying to tell us something important...
(BGM)
* Flag is `codegate2024{[found_string]}`.

$ sha256sum ./messages
0356d4c29863d2c7111635c28db23790a229be56676880857d107b1076284dc3 ./messages
$ sha256sum ./flag_enc
34146e91b149fa6474e8cc2a3348329d23ed76d4b9b6611c78a2f16c2684a673 ./flag_enc

file link: https://drive.google.com/file/d/1xvj706eiPD7RQ3gatCHM_mfQ8wqNblS5/view?usp=sharing
```

## Writeup
### Introduction
This was an interesting rev challenge that was hard enough to stretch me but easy enough for me to still solve within the 24 hour timeframe. I got the second solve and it took me about 5 hours to finish. You are given 2 files:

* A 64-bit x86 stripped executable [`messages`](/static/codegatectf-everlastingmessage/messages) written in C
* A 200 MB file of binary data called `flag_enc` (too big to include here)

Based on the name of the binary data and after initial inspection of the `main()` function in `messages`, the intended usage is `./messages input_file output_file`, and it was run with `flag` as the input and `flag_enc` as the output. Therefore, if we can determine the encrypting/encoding mechanism implemented in the binary, we can reverse that process and apply it to `flag_enc` to recover the initial `flag` file. Also, since `flag_enc` is ~200 MB, unless this encoding mechanism is **horribly** inefficient, we can assume the original `flag` file is about the same size and is probably an actual file type (like PNG or something) instead of a normal `flag.txt`.

My goal for this writeup is to clearly explain the steps I went through to understand the binary and implement the solution, perhaps even a little too in depth.

### Concepts/Functions to Understand
The first thing I always do when reversing a binary is understand any C functions being used that I do not know personally or very well. For writeup's sake, I'm going to define and explain all the important C functions and concepts used in this binary. 

#### File Opening & Reading
* `int open(const char *pathname, int flags, mode_t mode)`
    * When opening a file, the `open()` function is used. In C, this code looks like `open('file.txt', O_CREAT | O_RDWR, 0777)`. Notice how the flags are initialized as constants being ORed together; somewhere in glibc source code, these constants are set to a number with only 1 bit set, so if you OR 2 of these constants together, you get a number with 2 bits set. 
    * For example, `O_WRONLY` is set to `0b1` and `O_TRUNC` is set to `0b1000000000`, therefore `O_WRONLY | O_TRUNC` becomes `0b1000000001`, or 513. 
    * When code is compiled, those constant labels are lost and simply replaced with 513. When reverse engineering, you need to figure out what bits are set and which constants those correspond to in order to determine the original flags being passed (ChatGPT is pretty good at this).
    * When the `O_CREAT` flag is passed in and a file is being created, the third parameter `mode` is required (not necessary otherwise); `mode` specifies the file permissions on the created file in octal. So if you wanted to make the permissions 777, you'd pass in `0777` (note leading 0 for octal) which is `511` or `0x1ff`
    * The return value is a file descriptor (positive integer) that corresponds to that file.
* `ssize_t read(int fd, void buf[.count], size_t count)`
    * To read data from an open file, the `read()` function is used. The first argument is the file descriptor from the `open()` call, then a pointer to an array where the read contents are stored, then the maximum number of bytes to be read from the file. Note that consecutive calls to `read()` with the same fd will pick up where the previous call left off, meaning you don't read the same `count` bytes from the fd each time.

#### Message Queues
In an Operating System, messages queues are used to facilitate Inter-Process Communication (IPC) so different processes can talk and share data asynchronously. They use a sub/pub design where you can publish messages to a message queue and receive messages from a message queue. Message queues are created with `msgget()`, messages are sent using `msgsnd()`, messages are received using `msgrcv()`, and message queue commands are sent using `msgctl()`.

* `int msgget(key_t key, int msgflg)` ([ref](https://man7.org/linux/man-pages/man2/msgget.2.html))
    * Just like `open()`, constants are used for the `key` and `msgflg` arguments which can be found in `/usr/include/bits/ipc.h`.
    * If the key is `IPC_PRIVATE` (or `0`), then a new message queue is created with the file permissions set by `msgflg` in octal.
    * The response is an integer identifying the message queue, much like a file descriptor for opened files. We'll use msqid for shorthand.
* `int msgsnd(int msqid, const void msgp[.msgsz], size_t msgsz, int msgflg);` ([ref](https://man7.org/linux/man-pages/man2/msgrcv.2.html))
    * The first argument is the msqid, the second is a pointer to a `msgbuf` struct containing message data, the third argument contains the size of one of the `msgbuf` structs in `msgp`, and the last argument specifies flags.
    * When calling this function, it will wait until a message comes from another process before continuing on.
* `ssize_t msgrcv(int msqid, void msgp[.msgsz], size_t msgsz, long msgtyp, int msgflg);` ([ref](https://man7.org/linux/man-pages/man2/msgrcv.2.html))
    * Same as `msgsnd` except it sends the message to the message queue and continues. 
* `int msgctl(int msqid, int cmd, struct msqid_ds *buf);` ([ref](https://man7.org/linux/man-pages/man2/msgctl.2.html))
    * The `cmd` argument uses constants also which determine what the OS should do with the message queue in question. Note that the `cmd` `IPC_RMID` is `0` and means to destroy/remove the message queue. 

The second argument of `msgsnd` and `msgrcv` is a `msgbuf` struct which looks like this ([ref](https://man7.org/linux/man-pages/man2/msgrcv.2.html#DESCRIPTION)):
```c
struct msgbuf {
    long mtype;       /* message type, must be > 0 */
    char mtext[x];    /* message data of size x */
};
```

The `mtype` field is kind of like an identifier for the data going across message queues so you can tag it and say "this message is meant for this purpose" to deconflict multiple processes in the same queue looking for different types of messages.

Note that the size of the `mtext` field is variable depending on the needs of the program. For this challenge, this size is 0x10 bytes. I created this struct in Ghidra using the Data Type Manager window so I could set stack variables equal to this datatype:

<img src="/static/codegatectf-everlastingmessage/struct1.png" width="450px">

#### Process Threads
* `int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void *), void *restrict arg);`
    * To create a new thread in the same process, you can use the `pthread_create()` function. The first argument specifies where a pointer to the returned `pthread_t` object should be stored, the second argument specifies attributes about the created thread, the third argument is a pointer to a function that the thread should run on startup, and the fourth argument is a pointer to the singular argument function ran on startup.
    * Note that this only allows for a single argument to be passed to the function, so if the function requires multiple arguments a workaround like a single struct with all the arguments must be used instead.

In our case, there are multiple arguments being passed to the thread function with a custom struct that looks like this (dubbed `arg_struct`):
```c
struct arg_struct {
    long mtype;                 /* message type, must be > 0 */
    void * filter_function;     /* function to pull out specific nibbles from a variable */
    void * process_function;    /* function that "processes" nibbles from filter_function */
};
```

I also created this struct in Ghidra using the Data Type Manager:

<img src="/static/codegatectf-everlastingmessage/struct2.png" width="450px">

### `main()` Cleanup
After creating the custom structs, cleaning up data types and variable names, and adding comments, I was able to decompile the `main()` function into [much nicer code](/static/codegatectf-everlastingmessage/main.c) (see what it looked like in Ghidra before [here](/static/codegatectf-everlastingmessage/before.c)):

```c
/* STRUCTS */
struct msgbuf {
    long mtype;         /* message type, must be > 0 */
    char mtext[0x10];   /* message data of size 16 */
};
struct arg_struct {
    long mtype;                 /* message type, must be > 0 */
    void * filter_function;     /* function to pull out specific nibbles from a variable */
    void * process_function;    /* function that "processes" nibbles from filter_function */
};


/* FUNCTION DEFINITIONS */
uint filter1(char* param);
uint filter2(char* param);
uint filter3(char* param);
uint filter4(char* param);

uint process1(uint param);
uint process2(uint param);
uint process3(uint param);
uint process4(uint param);

void thread_run(arg_struct *arg);


/* GLOBALS */
int deliver_msg_queue;
int receive_msg_queue;
pthread_t *thread_array[4];     /* array to store created threads in main() */
arg_struct arg_array[4] = {     /* array to store arguments for thread_run() */
    {1, &filter1, &process1},
    {2, &filter2, &process2},
    {3, &filter3, &process3},
    {4, &filter4, &process4}
};


/* MAIN */
int main(int argc, char **argv) {
    char pad_len;
    int inp;
    int output;
    int out;
    ssize_t sVar3;
    long in_FS_OFFSET;
    int i;
    int j;
    int x;
    int y;
    ulong contents_pos;
    size_t results_len;
    ulong nread;
    msgbuf flag_chunk;
    char contents [0x500];
    char results [2568];
    long stack_canary;

    stack_canary = *(long *)(in_FS_OFFSET + 0x28);

    // ensure that the program is called with 2 arguments: ./messages input_file output_file
    if (argc < 3) {
        exit(-1);
    }

    // read input file
    inp = open(argv[1], 0 /* O_RDONLY */);
    if (inp < 0) {
        exit(-1);
    }

    // create output file with 0644 permissions
    output = open(argv[2], 0x42 /* O_CREAT | O_RDWR */, 0644);
    if (output < 0) {
        exit(-1);
    }

    // create a message queue with W/R permissions to send messages to the threads
    deliver_msg_queue = msgget(0,01666);
    if (deliver_msg_queue < 0) {
        exit(-1);
    }

    // create a message queue with W/R permissions to receive messages from the threads
    receive_msg_queue = msgget(0,01666);
    if (receive_msg_queue < 0) {
        exit(-1);
    }

    // create 4 threads that will run thread_run() with different arguments
    for (i = 0; i < 4; i++) {
        pthread_create(thread_array[i], NULL, thread_run, arg_array[i]);
    }


    do {
        // read 1280 bytes from input_file
        nread = read(inp, contents, 0x500);
        
        // if len(contents) is not a multiple of 10, pad until it is
        if (nread % 10 != 0) {
            pad_len = 10 - (nread + ((nread / 10 << 2) + (nread / 10)) * -2);
            for (j = 0; j < pad_len; j++) {
                contents[j+nread] = pad_len;
            }
            nread += pad_len;
        }

        // loop through the contents 10 bytes at a time
        results_len = 0;
        for (contents_pos = 0; contents_pos < nread; contents_pos += 10) {

            // send the chunk to each of the threads
            for (x = 1; x < 5; x++) {
                flag_chunk.mtype = x;
                flag_chunk.mtext._8_8_ = *(ulong *)(contents[contents_pos+8]);
                flag_chunk.mtext._0_8_ = *(ulong *)(contents[contents_pos]);

                out = msgsnd(deliver_msg_queue, &flag_chunk, 0x10, 0);
                if (out != 0) {
                    perror("msgsnd-m");
                }
            }

            // receive the processed chunk from each of the threads and store in results buffer
            for (y = 1; y < 5; y++) {
                sVar3 = msgrcv(receive_msg_queue, &flag_chunk, 0x10, y, 0);
                if (sVar3 < 0) {
                    perror("msgrcv-m");
                }
                
                // copy the 5-byte message text to the results array
                memcpy(results[(y-1)*5 + results_len], flag_chunk.mtext, 5);
            }
            results_len += 0x14;
        }

        // write the "processed" data to the output file
        write(output, results, results_len);
    } while (0x4ff < nread); // keep reading bytes from the input file until we reach the end


    // cleanup
    out = msgctl(deliver_msg_queue, 0 /* IPC_RMID */, NULL);
    if (out == -1) {
        exit(1);
    }

    out = msgctl(receive_msg_queue, 0 /* IPC_RMID */, NULL);
    if (out == -1) {
        exit(1);
    }

    close(inp);
    close(output);

    if (stack_canary == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
    }
    __stack_chk_fail();
}
```

Here's the written rundown of what `main()` does:
* First argument is file with input, second argument is file for output
* Create 2 message queues, one to send data to threads and one to receive responses from the threads
* Create 4 threads for processing data from input file
* Read the content from the input file (padding to a multiple of 10 bytes) and split into chunks of 10 bytes
* Send the 10-byte chunk to each of the threads using a message queue
* Receive a response from each of the threads using a message queue and write it to the output file

So it seems the actual encoding/processing functionality takes place in the threads (for obfuscation purposes? efficiency sake?) and `main()` is just the taskmanager. Time to analyze the thread functions!

### `thread_run()` Cleanup
I cleaned up the `thread_run` function which [looks like this](/static/codegatectf-everlastingmessage/thread_run.c):

```c
/* STRUCTS */
struct msgbuf {
    long mtype;         /* message type, must be > 0 */
    char mtext[0x10];   /* message data of size 16 */
};
struct arg_struct {
    long mtype;                 /* message type, must be > 0 */
    void * filter_function;     /* function to pull out specific nibbles from a variable */
    void * process_function;    /* function that "processes" nibbles from filter_function */
};


/* GLOBALS */
int deliver_msg_queue;
int receive_msg_queue;


/* THREAD_RUN */
void thread_run(arg_struct *arg) {
    long stack_canary;
    int rand1;
    int rand2;
    ssize_t sVar2;
    ulong flag_segment;
    ulong output;
    long in_FS_OFFSET;
    msgbuf message;

    stack_canary = *(long *)(in_FS_OFFSET + 0x28);

    // process 10-byte chunks until message queue dies
    do {
        // get message from deliver_msg_queue
        sVar2 = msgrcv(deliver_msg_queue, &message, 0x10, &arg->mtype, 0);

        // use the filter_function on the 10-byte chunk to pull out 5 nibbles
        flag_segment = (*(code *)arg->filter_function)(message.mtext);

        // process the 5 nibbles from the filter_function
        output = (*(code *)arg->process_function)(flag_segment);

        // flip 0-2 random bits of the output
        rand1 = rand();
        rand2 = rand();
        message.mtext._0_8_ = (1 << (rand2 & 0x3f)) ^ (1 << (rand1 & 0x3f)) ^ output;
            /* 
                Note that the output will be a 5-byte integer, and the "bit" that is flipped 
                can be any bit in a 8-byte integer, so it's possible that the "flipped" bit is
                not relevant (since only 5 bytes are written to output file).

                In addition, it's possible the same bit is flipped twice. 

                Therefore, 0-2 random bits are flipped.
            */
        
        // send the response to receive_msg_queue
        message.mtype = &arg->mtype;
        rand1 = msgsnd(receive_msg_queue, &message, 0x10, 0);
    } while (sVar2 >= 0);

    if (stack_canary == *(long *)(in_FS_OFFSET + 0x28)) {
        return;
    }
    __stack_chk_fail();
}
```

Here's the written rundown of what `thread_run()` does:
* Get a 10-byte chunk from `main()`, pull out 5 nibbles, and run those nibbles through processing_function (3rd field of function argument)
* Flip 0-2 random bits of the 5-byte output
* Send the 5-byte output back to `main()` to be written to the output file

There's a couple important things to note going on here. First, this conversion process is lossy since random bits are flipped. However, the processing functions take in 5 nibbles and gives out 5 bytes (much larger keyspace). This means that even with lossy data, the chance of collisions (two nibbles each with 0-2 random flipped bits producing the same 5-byte output) is very small. A bit of brute force, luck, and tolerance for corrupted data should get us through that.

Second, each thread has a different `filtering_function` and `processing_function`. The first thread takes the first 5 nibbles, the second thread takes the next 5 nibbles, etc., so threads don't process the same data ever. Also, the processing functions do a lot of binary arithmetic but are not dependent on any outside factors or previous inputs so they are deterministic. Since there are only `16 ** 5 = 1_048_576` input possibilities, that means we can map all possible inputs to the output for each function. Note that the processing functions are like a thousand binary arithmetic operations and is not meant to be statically reversed lol.

### Approach to Solve
Now that we've reversed the program and understand what it does, a solution is in sight:

1. First, we need to script GDB to run each of the processing functions with all possible inputs and retrieve the outputs (this way we can figure out what 5-nibble input produced the 5-byte output we have). 
2. Second, we need to read in `flag_enc` and split it into 20-byte chunks. For each chunk, we need to split that into 4x 5-byte sections (the 5-byte output from each thread) and generate all variations of that 5-byte segment with 0-2 random bit flips. 
3. Third, we look through our map from Step 1 to see which of the 5-byte variations actually map to a 5-nibble input (there should only be 1 most of the time).
4. Fourth, take the 5-nibble input we get from Step 3 and write it to a file to recover the original file.

Since this was a lot of computations to do, I decided to parallelize the work by splitting `flag_enc` into 8 files and running my solve script in 8 different terminals. This is scripted in [`split.py`](/static/codegatectf-everlastingmessage/split.py) (I did last 20 bytes by hand):

```python
def split(input_file):
    with open(input_file, 'rb') as f:
        data = f.read()
    l = len(data)
    t = l // 8
    t = (t // 10) * 10
    for i in range(8):
        s = i * t
        e = (i + 1) * t
        with open(f'flag_enc_{i + 1}', 'wb') as c:
            c.write(data[s:e])

split('flag_enc')
```

I wrote a Python script to run the `./messages` binary in GDB and call each of the four processing functions using their non-ASLR addresses with all possible inputs in [`calculate.py`](/static/codegatectf-everlastingmessage/calculate.py) by running `gdb -q -x calculate.py`:

```python
### MAP INPUTS TO OUTPUTS ###
# import GDB stuff
import gdb
ge = gdb.execute
parse = gdb.parse_and_eval
import json

# set up break points
BASE = 0x00555555554000
FUNCS = []
FUNCS.append(BASE+0x12e9)
FUNCS.append(BASE+0x264d)
FUNCS.append(BASE+0x3977)
FUNCS.append(BASE+0x4c0e)

# set up debugging
ge('aslr off')
ge('file messages')
ge('b open')
ge('run input output8')
ge('finish')


# get output for each possible 5-nibble input
for x, func in enumerate(FUNCS):
    output = []
    for i in range(0xfffff):
        if i % 0x1000 == 0:
            print(hex(i))
        inp = i
        out = ge(f'call ((long(*)(long)){func})({hex(inp)})', to_string=True).split(' = ')[1].strip()
        output.append(out)
    
    with open(f'output{x}.json', 'w') as f:
        json.dump(output, f)
```

That script gave me 4 JSON files that I could import into my final solve script. I then wrote a script that reads in those JSON files, formats the data as a dictionary with `key:value` pairs as `output:input` pairs, and does steps 2-4 using some probably overly complicated Python shenanigans. ChatGPT helped write my helper functions. Note that my script was missing something because even with all 0-2 random bit flips on a 5-byte output, sometimes none of them matched to a 5-nibble input. In that case, I just arbitrarily set the input as `0xfffff` and hoped the corrupted data wouldn't be too bad. That resulted in [this script](/static/codegatectf-everlastingmessage/solve.py):

```python
import sys

arg = int(sys.argv[1])


### SETUP ###
# imports
import json

# load the outputs
func1_out = json.load(open('output0.json'))
func2_out = json.load(open('output1.json'))
func3_out = json.load(open('output2.json'))
func4_out = json.load(open('output3.json'))

# convert the outputs to a dictionary
func1_out = {int(v,16): x for x, v in enumerate(func1_out)}
func2_out = {int(v,16): x for x, v in enumerate(func2_out)}
func3_out = {int(v,16): x for x, v in enumerate(func3_out)}
func4_out = {int(v,16): x for x, v in enumerate(func4_out)}



### HELPER FUNCTIONS ###
import itertools

def flip_bits(n, bit_positions):
    """Flip the bits in `n` at the positions specified in `bit_positions`."""
    for pos in bit_positions:
        n ^= (1 << pos)
    return n

def generate_possibilities(initial_value):
    bit_length = 40  # 5 bytes = 40 bits
    bit_positions = range(bit_length)
    flipped_values = []

    # Generate all combinations of 2 bit positions
    for pos1, pos2 in itertools.combinations(bit_positions, 2):
        # Create a copy of the initial value
        new_value = flip_bits(initial_value, [pos1, pos2])
        flipped_values.append(new_value)

    # generate all combinations of 1 bit positions
    for pos in bit_positions:
        new_value = flip_bits(initial_value, [pos])
        flipped_values.append(new_value)

    return flipped_values+[initial_value]



### SOLVE ###
# split flag_enc into 20-byte chunks
enc = open(f'flag_enc_{arg}', 'rb').read()
chunks = [enc[i:i+20] for i in range(0, len(enc), 20)]

print("Starting")

for chunk in chunks:
    #print(chunk)
    # steps 1 & 2
    func1 = int.from_bytes(bytes.fromhex(chunk[0:5].hex()),'little')
    func2 = int.from_bytes(bytes.fromhex(chunk[5:10].hex()),'little')
    func3 = int.from_bytes(bytes.fromhex(chunk[10:15].hex()),'little')
    func4 = int.from_bytes(bytes.fromhex(chunk[15:20].hex()),'little')

    # calculate possibilities for func1 (2 random bit flips)
    for x in generate_possibilities(func1):
        if func1_out.get(x, None) is not None:
            y = func1_out.get(x, None)
            break
    else:
        print('Failed to find func1',chunk)
        y = 0xfffff

    # calculate possibilities for func2 (2 random bit flips)
    for x in generate_possibilities(func2):
        if func2_out.get(x, None) is not None:
            x = func2_out.get(x, None)
            break
    else:
        print('Failed to find func2',chunk)
        x = 0xfffff

    b = bytes.fromhex(hex(int.from_bytes(bytes.fromhex(hex(x << 20 | y)[2:].zfill(10)),'little'))[2:].zfill(10))
    with open(f'flag_{arg}','ab') as f:
        f.write(b)

    

    # calculate possibilities for func3 (2 random bit flips)
    for x in generate_possibilities(func3):
        if func3_out.get(x, None) is not None:
            y = func3_out.get(x, None)
            break
    else:
        print('Failed to find func3',chunk)
        y = 0xfffff

    # calculate possibilities for func4 (2 random bit flips)
    for x in generate_possibilities(func4):
        if func4_out.get(x, None) is not None:
            x = func4_out.get(x, None)
            break
    else:
        print('Failed to find func4',chunk)
        x = 0xfffff

    b = bytes.fromhex(hex(int.from_bytes(bytes.fromhex(hex(x << 20 | y)[2:].zfill(10)),'little'))[2:].zfill(10))
    with open(f'flag_{arg}','ab') as f:
        f.write(b)
```

Running across all 8 terminals, it took about 40 minutes to complete. At that point, I just ran `cat flag_1 flag_2 flag_3 flag_4 flag_5 flag_6 flag_7 flag_8 > flag.mp4` to get the mp4 file. It was corrupted, but uploading it to [an online site](https://fix.video/) to fix it gave me [a video that worked](/static/codegatectf-everlastingmessage/flag.mp4)!

**Flag:** `codegate2024{fun_fun_coding_theory}`