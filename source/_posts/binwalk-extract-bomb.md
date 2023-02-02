---
title: Binwalk Extract Bomb
date: 2023-02-01 00:00:00
tags: 
- security-research
- forensics
---

# Binwalk Extract Bomb
While playtesting a CTF problem created by my friend for an internal BYU CTF, I found that running a 200 MB file through [binwalk](https://www.kali.org/tools/binwalk/) and extracting all found files was taking hours and had occupied almost **an entire terabyte** of space! After a little bit of research and some fun, I've devised binwalk's counterpart to the [zip bomb](https://en.wikipedia.org/wiki/Zip_bomb)! If you aren't familiar with a zip bomb, it's a small ZIP file that contains several layers of nested ZIP files that, when recursively extracted, fills up an obnoxious amount of space! One example called [42.zip](https://unforgettable.dk/) is only 42 KB in size, and when fully extracted, expands to 4.5 **petabytes** of files (4.5 thousand thousand thousand thousand KBs). 

My fully optimized binwalk extract bomb does the same as the zip bomb. An <u>8 MB file can expand to 4 terabytes</u>, and <u>an 800 MB file can expand to 40 petabytes</u>, only by running `binwalk -e file`! See details below.

## How the Bomb Works
Binwalk is an open-source software intended to be used for firmware analysis and reverse engineering. It's also commonly used in the real world and in CTFs to detect hidden files (like in steganography) and extract these files. It's built to recognize these files by identifying "magic bytes", or a specific sequence of bytes that says "This is the start of a PDF" or "This is the start of a PNG". Depending on the file type, it will parse the continuing bytes to determine metadata of the file. When given a file with multiple files appended afterwards or placed somewhere in the middle, it will identify these files. To extract these files, the argument `-e` is used. 

The quirk is found in the underlying fact that some files only have headers and not footers. Without a footer, how can binwalk know where one file ends and another file begins? If the utility assumes that the file ends where another set of magic bytes is found, it may be missing bytes if the magic bytes are just a coincidence and actually part of the original file. To deal with this, the software simply extracts all the data from those magic bytes **to the end of the file**, regardless of the length ([this is intended behavior](https://github.com/ReFirmLabs/binwalk/wiki/Frequently-Asked-Questions#why-are-some-extracted-files-larger-than-expected) and a disclaimer is present in FAQs). 

As an example, let's say you have three files (without footers) appended to each other and you run binwalk on it. If you identify all three sets of magic bytes marking the beginning of each file and attempt to extract them, it will run as so: the first file will be the entire length of the file; the second file will be from the second set of magic bytes to the end of the file; the third file will be from the third set of magic bytes to the end of the file. It looks like so:

```
---------------                ---------------
|             |                |             |
| First file  |                |             |
|             |                |             |
|-------------|                |             |     ---------------
|             |                |             |     |             |
| Second file |  =(extract)=>  | First file  |     |             |
|             |                |             |  +  |             |
|-------------|                |             |     | Second file |     ---------------
|             |                |             |     |             |  +  |             |
| Third file  |                |             |     |             |     | Third file  |
|             |                |             |     |             |     |             |
---------------                ---------------     ---------------     ---------------
```

It should be fairly apparent that the total size of extracted data gets MUCH larger than the original data. The more "appended files" in a single file, the more extracted files there are. The smaller each original file is, the more "appended files" you can fit in a single KB or MB file. 

## Specifications
The footer-less file chosen for the most optimized binwalk extract bomb is an 8-byte compressed ZLIB file of an empty string - `\x78\x9c\x03\x00\x00\x00\x00\x01`. I wrote [a simple Python script](/static/binwalk-extract-bomb/gen.py) that can dynamically generate an output file with an arbitrary amount of these ZLIB files:

```python
import zlib

REPETITIONS = 1000000
compressed = zlib.compress(b'')*REPETITIONS

with open('outfile', 'wb') as f:
    f.write(compressed)
```

Running the above script as it is would generate a single file called `outfile` with 1 million copies of the 8-byte ZLIB file appended to each other. When extracted with the single command `binwalk -e outfile`, the resulting files will occupy a total of 4 terabytes. A table with specifications is below:

| REPETITIONS | SIZE   | EXTRACTED | MULTIPLIER    | DOWNLOAD LINK |
| ----------- | ------ | --------- | ------------- | ------------- |
| 10          | 80 B   | 440 B     | x5.5          | [Link](/static/binwalk-extract-bomb/10_reps.zlib) |
| 100         | 800 B  | 40.4 KB   | x50.5         | [Link](/static/binwalk-extract-bomb/100_reps.zlib) |
| 1,000       | 8 KB   | 4.00 MB   | x500.5        | [Link](/static/binwalk-extract-bomb/1000_reps.zlib) |
| 10,000      | 80 KB  | 400 MB    | x5,000.5      |               |
| 100,000     | 800 KB | 40.0 GB   | x50,000.5     |               |
| 1,000,000   | 8 MB   | 4.0 TB    | x500,000.5    | [Link](/static/binwalk-extract-bomb/1mil_reps.zlib) |
| 10,000,000  | 80 MB  | 400 TB    | x5,000,000.5  |               |
| 100,000,000 | 800 MB | 40.0 PB   | x50,000,000.5 |               |


## Mitigations
The mitigation depends on the exploitation scenario. However, here are some generic mitigation strategies that may be useful:

* For parsers or services that use binwalk to automatically extract files, you can use the `--size` argument to limit the size of each extracted file. 
    * As an example, if you set the `--size` argument to 1 KB, then the 8 MB, 1 million repetition bomb (which would normally expand to 4 terabytes) will only expand to 1,000,000 * 1,000 bytes = 1 GB. If the `--size` argument is set to 1 MB, then the bomb would expand to 1 TB of output (which is still fairly large).
* Before running `binwalk -e outfile`, run `binwalk outfile` and see how many files are detected. If a million files are detected, this is probably a sign that you don't want to extract it/everything (my preferred mitigation).
* Use another tool since this tool is specifically designed for firmware analysis. 