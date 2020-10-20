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
PACKET_QDISC_BYPASS = 20 
TPACKET_V2 = 1
TPACKET_V3 = 2
PACKET_RX_RING = 5 
PACKET_TX_RING = 13 
PACKET_LOSS = 14
MAP_LOCKED	= 0x02000
MAP_POPULATE = 0x08000

#status of rx tx ring 

TP_STATUS_USER = 1 << 0 
TP_STATUS_KERNEL = 0
TP_STATUS_SEND_REQUEST = 1
TP_STATUS_SENDING = 1 << 1
MSG_DONTWAIT = 0x40
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

class tpacket_req(Packet):
    __hdr__ = (
        ('tp_block_size','I',0),
        ('tp_block_nr','I',0),
        ('tp_frame_size','I',0),
        ('tp_frame_nr','I',0)
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
    def rx_packets(self,conn=None):
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
                if conn is None:
                    status = yield self.mem[tmp+tphdr3.tp_mac:tmp+tphdr3.tp_mac+tphdr3.tp_snaplen]
                else:
                    conn.send_bytes(self.mem[tmp+tphdr3.tp_mac:tmp+tphdr3.tp_mac+tphdr3.tp_snaplen])
                tmp = tmp + tphdr3.tp_next_offset 
                tphdr3 = tpacket3_hdr(self.mem[tmp:off_end])
            bdesc.block_status = TP_STATUS_KERNEL
            i = (i + 1) % self.bnum
    def rx_fast_packets(self,conn=None):
        pfd = select.poll()
        pfd.register(self.sock,select.POLLIN | select.POLLERR)
        i = 0
        while True:
            offset = i * self.bsize
            status = ctypes.c_uint.from_buffer(self.mem,offset+8)
            if (status.value & TP_STATUS_USER) == 0:
                pfd.poll(-1)
                continue
            pkt_nums = ctypes.c_uint.from_buffer(self.mem,offset+12).value
            tmp = offset + ctypes.c_uint.from_buffer(self.mem,16).value 
            pkt_start = ctypes.c_ushort.from_buffer(self.mem,tmp+24).value
            pkt_len = ctypes.c_uint.from_buffer(self.mem,tmp+12).value
            pkt_next = ctypes.c_uint.from_buffer(self.mem,tmp).value
            for _ in range(pkt_nums):
                yield self.mem[tmp+pkt_start:tmp+pkt_start+pkt_len]
                tmp += pkt_next
                pkt_start = ctypes.c_ushort.from_buffer(self.mem,tmp+24).value
                pkt_len = ctypes.c_uint.from_buffer(self.mem,tmp+12).value
                pkt_next = ctypes.c_uint.from_buffer(self.mem,tmp).value
            status.value = TP_STATUS_KERNEL
            i = (i + 1) % self.bnum
    def close(self):
        self.mem.close()
        self.sock.close()

class txRawSocket():
    def __init__(self,interface:str,proto=0,fsize = frame_size,
        fnum=frame_num,bsize=block_size,bnum=block_num,bypass_qdisc=1):
        self.fsize = frame_size
        self.fnum = frame_num
        self.iface = interface
        try:
            self.sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(proto))
            self.sock.setsockopt(SOL_PACKET,PACKET_VERSION,TPACKET_V2)
            self.sock.setsockopt(SOL_PACKET,PACKET_QDISC_BYPASS,bypass_qdisc)
            self.sock.setsockopt(SOL_PACKET,PACKET_LOSS,1)
        except Exception as identifier:
            log_sys.critical("create raw socket error :%s" % repr(identifier))
            raise SystemExit
        try:
            tpacket = tpacket_req()
            tpacket.tp_block_size = bsize
            tpacket.tp_block_nr = bnum
            tpacket.tp_frame_size = fsize
            tpacket.tp_frame_nr = fnum
            self.sock.setsockopt(SOL_PACKET,PACKET_TX_RING,tpacket.pack())
            self.mem = mmap.mmap(self.sock.fileno(),bsize*bnum,mmap.MAP_SHARED|MAP_LOCKED|MAP_POPULATE,
                mmap.PROT_READ|mmap.PROT_WRITE)
        except Exception as identifier:
            log_sys.critical("set raw socket opt of ring tx error :%s %d" % (repr(identifier),identifier.__traceback__.tb_lineno))
            self.sock.close()
            raise SystemExit
        try:
            self.sock.bind((interface,0,0,0))
        except Exception as identifier:
            self.sock.close()
            log_sys.critical("raw socket bind error :%s" % repr(identifier))
            raise SystemExit
    def send_packets(self,packet:bytes,num=0):
        always = True if num == 0 else False
        pkt_len = len(packet)
        i = 0
        offset = i * self.fsize
        while num or always:
            status = ctypes.c_uint.from_buffer(self.mem,offset)
            tp_len = ctypes.c_uint.from_buffer(self.mem,offset+4)
            tp_snaplen = ctypes.c_uint.from_buffer(self.mem,offset+8)
            if status.value & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING):
                self.sock.sendto(b'',MSG_DONTWAIT,(self.iface,0,0,0))
                continue
            tp_len.value = pkt_len
            tp_snaplen.value = pkt_len
            self.mem[offset+32:offset+32+pkt_len] = packet
            status.value = TP_STATUS_SEND_REQUEST
            i = (i + 1) % self.fnum
            offset = i * self.fsize
            num -= 1
        self.sock.sendto(b'',0,(self.iface,0,0,0))

