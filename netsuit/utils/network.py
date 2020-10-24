import sys 
import array


def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array('H',pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    if sys.byteorder == 'little':
        s = (s >> 8 & 0xff) | s << 8
    return s & 0xffff