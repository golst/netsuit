import socket 
import mmap 
import ctypes 
import struct 
import select 
import fcntl 
import sys 
from netsuit.dpkt.dpkt import Packet
from netsuit.log import log_sys

frame_size = 1 << 11
block_size = 1 << 22

#the default number of frame is 128k
block_num = 64 
frame_num = 64 * (block_size // frame_size)

#proto to listen
ETH_P_ALL = 0x0003

#some defines about pf_socket
SOL_PACKET = 263
PACKET_VERSION = 10
TPACKET_V2 = 1
TPACKET_V3 = 2
PACKET_RX_RING = 5 
MAP_LOCKED	= 0x02000

#status of rx tx ring 

TP_STATUS_USER = 1 << 0 
TP_STATUS_KERNEL = 0

class tpacket_req3(Packet):
    __hdr__ = (
        ('tp_block_size','I',0),
        ('tp_block_nr','I',0),
        ('tp_frame_size','I',0),
        ('tp_frame_nr','I',0),
        ('tp_retire_blk_tov','I',0),
        ('tp_sizeof_priv','I',0),
        ('tp_feature_req_word','I',0)
    )
    __byte_order__ = '<' if sys.byteorder == 'little' else '>'
class block_desc(Packet):
    __hdr__ = (
        ('version','I',0),
        ('offset_to_priv','I',0),
        ('block_status','I',0),
        ('num_pkts','I',0),
        ('offset_to_first_pkt','I',0)
    )
    __byte_order__ = '<' if sys.byteorder == 'little' else '>'

class tpacket3_hdr(Packet):
    __hdr__ = (
        ('tp_next_offset','I',0),
        ('tp_sec','I',0),
        ('tp_nsec','I',0),
        ('tp_snaplen','I',0),
        ('tp_len','I',0),
        ('tp_status','I',0),
        ('tp_mac','H',0),
        ('tp_net','H',0)
    )
    __byte_order__ = '<' if sys.byteorder == 'little' else '>'


class rxRawSocket():
    def __init__(self,interface:str,proto=ETH_P_ALL,fsize = frame_size,
        fnum=frame_num,bsize=block_size,bnum=block_num):
        self.bsize = bsize
        self.bnum = bnum
        try:
            self.sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(proto))
            self.sock.setsockopt(SOL_PACKET,PACKET_VERSION,TPACKET_V3)
        except Exception as identifier:
            log_sys.critical("create raw socket error :%s" % repr(identifier))
            raise SystemExit
        try:
            tpacketv3 = tpacket_req3()
            tpacketv3.tp_block_size = bsize
            tpacketv3.tp_block_nr = bnum
            tpacketv3.tp_frame_size = fsize
            tpacketv3.tp_frame_nr = fnum 
            tpacketv3.tp_retire_blk_tov = 60
            tpacketv3.tp_sizeof_priv = 0
            tpacketv3.tp_feature_req_word = 1
            self.sock.setsockopt(SOL_PACKET,PACKET_RX_RING,tpacketv3.pack())
            self.mem = mmap.mmap(self.sock.fileno(),bsize*bnum,mmap.MAP_SHARED|MAP_LOCKED,
                mmap.PROT_READ|mmap.PROT_WRITE)
        except Exception as identifier:
            log_sys.critical("set raw socket opt of ring rx error :%s %d" % (repr(identifier),identifier.__traceback__.tb_lineno))
            self.sock.close()
            raise SystemExit
        try:
            self.sock.bind((interface,0,0,0))
        except Exception as identifier:
            self.sock.close()
            log_sys.critical("raw socket bind error :%s" % repr(identifier))
            raise SystemExit
    def rx_packets(self):
        pfd = select.poll()
        pfd.register(self.sock,select.POLLIN | select.POLLERR)
        i = 0
        while True:
            offset = i * self.bsize
            off_end = offset+self.bsize
            bdesc = block_desc(self.mem[offset:off_end])
            if (bdesc.block_status & TP_STATUS_USER) == 0:
                pfd.poll(-1)
                continue
            tmp = offset + bdesc.offset_to_first_pkt
            tphdr3 = tpacket3_hdr(self.mem[tmp:off_end])
            for _ in range(bdesc.num_pkts):
                status = yield self.mem[tmp+tphdr3.tp_mac:off_end]
                tphdr3 = tpacket3_hdr(self.mem[tmp+tphdr3.tp_next_offset:off_end])
            bdesc.block_status = TP_STATUS_KERNEL
            i = (i + 1) % self.bnum
        
            
class txRawSocket():
    pass 

