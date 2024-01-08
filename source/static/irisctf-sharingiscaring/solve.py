import math
from hashlib import md5


### SIGNAL DATA ###
signal_data = eval(open('signal.txt','r').read())

# split signal_data into lists of 1600
data_segments = [signal_data[i:i+1600] for i in range(0, len(signal_data), 1600)]
#print(data_segments)


### KEYS ###
# keys in binary format (ie b'\x99\x34\x12')
keys_b = [0, 0, 0, 0, 0]
keys_b[0] = open('1.key','rb').read()
keys_b[1] = open('2.key','rb').read()
keys_b[2] = open('3.key','rb').read()
keys_b[3] = open('4.key','rb').read()
keys_b[4] = open('alice.key','rb').read()

# keys in string format (ie ['1','0','1','0','1','0','1','0'])
keys_s = []
for k in keys_b:
    keys_s.append([x for x in''.join([bin(x)[2:].zfill(8) for x in k])])

# keys in decoded format where 1 is -1 and 0 is 1
keys_d = []

for k in keys_s:
    tmp0 = []
    tmp1 = []
    for i in range(len(k)):
        if k[i] == '1':
            tmp0.append(-1)
            tmp1.append(1)
        else:
            tmp0.append(1)
            tmp1.append(-1)

    keys_d.append({'0':tmp0,'1':tmp1})



### MESSAGE VARIATIONS ###
def get_seq(key1, key2, key3, key4, key5):
    retval = []
    for i in range(len(key1)):
        retval.append(key1[i] + key2[i] + key3[i] + key4[i] + key5[i])

    hash = md5(''.join([str(x) for x in retval]).encode()).hexdigest()
    return hash
variations = []

# i know this isn't good programming but idc
variations.append(("00000",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("00001",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("00010",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("00011",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("00100",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("00101",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("00110",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("00111",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("01000",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("01001",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("01010",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("01011",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("01100",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("01101",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("01110",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("01111",get_seq(keys_d[0]['0'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("10000",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("10001",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("10010",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("10011",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("10100",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("10101",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("10110",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("10111",get_seq(keys_d[0]['1'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("11000",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("11001",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("11010",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("11011",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("11100",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("11101",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("11110",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("11111",get_seq(keys_d[0]['1'],keys_d[1]['1'],keys_d[2]['1'],keys_d[3]['1'],keys_d[4]['1'])))
print(variations)


### LOOP THROUGH SEGMENTS ###
for segment in data_segments:
    hash = md5(''.join([str(x) for x in segment]).encode()).hexdigest()

    for variation in variations:
        if hash == variation[1]:
            print(variation[0][-1],end='')
            break
    else:
        print("ERROR: hash not found")