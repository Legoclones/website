import zlib

REPETITIONS = 1000000
compressed = zlib.compress(b'')*REPETITIONS

with open('out_1000.zlib', 'wb') as f:
    f.write(compressed)