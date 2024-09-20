import serial

game = b'\xa1\xec' # set I to 0x1fc

s = serial.Serial('COM5')
s.write(b"play xxx\x01\x01\x01" + game + b'\r')
res = s.read_until(b'\r')
print(res)

'''
66 6c 61 67 7b 43 4c 30 35 33 5f 54 30 5f 46 30 4e 54 53 5f 7d
'''