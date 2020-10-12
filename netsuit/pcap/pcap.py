import sys
import time
from decimal import Decimal

from netsuit.dpkt import dpkt
from netsuit.utils.compat import intround

# pcap file header magic

TCPDUMP_MAGIC = 0xa1b2c3d4
TCPDUMP_MAGIC_NANO = 0xa1b23c4d
PMUDPCT_MAGIC = 0xd4c3b2a1
PMUDPCT_MAGIC_NANO = 0x4d3cb2a1

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

# the packet type  in the pcap file
DLT_NULL = 0
DLT_EN10MB = 1
DLT_EN3MB = 2
DLT_AX25 = 3
DLT_PRONET = 4
DLT_CHAOS = 5
DLT_IEEE802 = 6
DLT_ARCNET = 7
DLT_SLIP = 8
DLT_PPP = 9
DLT_FDDI = 10
DLT_PFSYNC = 18
DLT_PPP_SERIAL = 50
DLT_PPP_ETHER = 51
DLT_ATM_RFC1483 = 100
DLT_RAW = 101
DLT_C_HDLC = 104
DLT_IEEE802_11 = 105
DLT_FRELAY = 107
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_LTALK = 114
DLT_PFLOG = 117
DLT_PRISM_HEADER = 119
DLT_IP_OVER_FC = 122
DLT_SUNATM = 123
DLT_IEEE802_11_RADIO = 127
DLT_ARCNET_LINUX = 129
DLT_APPLE_IP_OVER_IEEE1394 = 138
DLT_MTP2_WITH_PHDR = 139
DLT_MTP2 = 140
DLT_MTP3 = 141
DLT_SCCP = 142
DLT_DOCSIS = 143
DLT_LINUX_IRDA = 144
DLT_USER0 = 147
DLT_USER1 = 148
DLT_USER2 = 149
DLT_USER3 = 150
DLT_USER4 = 151
DLT_USER5 = 152
DLT_USER6 = 153
DLT_USER7 = 154
DLT_USER8 = 155
DLT_USER9 = 156
DLT_USER10 = 157
DLT_USER11 = 158
DLT_USER12 = 159
DLT_USER13 = 160
DLT_USER14 = 161
DLT_USER15 = 162
DLT_IEEE802_11_RADIO_AVS = 163
DLT_BACNET_MS_TP = 165
DLT_PPP_PPPD = 166
DLT_GPRS_LLC = 169
DLT_GPF_T = 170
DLT_GPF_F = 171
DLT_LINUX_LAPD = 177
DLT_BLUETOOTH_HCI_H4 = 187
DLT_USB_LINUX = 189
DLT_PPI = 192
DLT_IEEE802_15_4 = 195
DLT_SITA = 196
DLT_ERF = 197
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_AX25_KISS = 202
DLT_LAPD = 203
DLT_PPP_WITH_DIR = 204
DLT_C_HDLC_WITH_DIR = 205
DLT_FRELAY_WITH_DIR = 206
DLT_IPMB_LINUX = 209
DLT_IEEE802_15_4_NONASK_PHY = 215
DLT_USB_LINUX_MMAPPED = 220
DLT_FC_2 = 224
DLT_FC_2_WITH_FRAME_DELIMS = 225
DLT_IPNET = 226
DLT_CAN_SOCKETCAN = 227
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_IEEE802_15_4_NOFCS = 230
DLT_DBUS = 231
DLT_DVB_CI = 235
DLT_MUX27010 = 236
DLT_STANAG_5066_D_PDU = 237
DLT_NFLOG = 239
DLT_NETANALYZER = 240
DLT_NETANALYZER_TRANSPARENT = 241
DLT_IPOIB = 242
DLT_MPEG_2_TS = 243
DLT_NG40 = 244
DLT_NFC_LLCP = 245
DLT_INFINIBAND = 247
DLT_SCTP = 248
DLT_USBPCAP = 249
DLT_RTAC_SERIAL = 250
DLT_BLUETOOTH_LE_LL = 251
DLT_NETLINK = 253
DLT_BLUETOOTH_LINUX_MONITOR = 253
DLT_BLUETOOTH_BREDR_BB = 255
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_PROFIBUS_DL = 257
DLT_PKTAP = 258
DLT_EPON = 259
DLT_IPMI_HPM_2 = 260
DLT_ZWAVE_R1_R2 = 261
DLT_ZWAVE_R3 = 262
DLT_WATTSTOPPER_DLM = 263
DLT_ISO_14443 = 264
if sys.platform.find('openbsd') != -1:
    DLT_LOOP = 12
    DLT_RAW = 14
else:
    DLT_LOOP = 108
    DLT_RAW = 12

# don't known the function of dltoff
dltoff = {DLT_NULL: 4, DLT_EN10MB: 14, DLT_IEEE802: 22, DLT_ARCNET: 6,
          DLT_SLIP: 16, DLT_PPP: 4, DLT_FDDI: 21, DLT_PFLOG: 48, DLT_PFSYNC: 4,
          DLT_LOOP: 4, DLT_LINUX_SLL: 16}

# the format of each packet
# the default bytes order is big debian
class PktHdr(dpkt.Packet):
    __hdr__ = (
        ('tv_sec', 'I', 0),
        ('tv_usec', 'I', 0),
        ('caplen', 'I', 0),
        ('len', 'I', 0),
    )

class LEPktHdr(PktHdr):
    __byte_order__ = '<'

# the format of pcap file
# the default byte order is big debian

class FileHdr(dpkt.Packet):
    __hdr__ = (
        ('magic', 'I', TCPDUMP_MAGIC),
        ('v_major', 'H', PCAP_VERSION_MAJOR),
        ('v_minor', 'H', PCAP_VERSION_MINOR),
        ('thiszone', 'I', 0),
        ('sigfigs', 'I', 0),
        ('snaplen', 'I', 1500),
        ('linktype', 'I', 1),
    )
class LEFileHdr(FileHdr):
    __byte_order__ = '<'

# the writer of pcap file

class Writer():
    __le = sys.byteorder == 'little'

    def __init__(self,fileobj,snaplen = 1500, linktype = DLT_EN10MB, nano = False):
        self.__f = fileobj
        self._precision = 9 if nano else 6
        self._precision_multiplier = 10**self._precision
        magic = TCPDUMP_MAGIC_NANO if nano else TCPDUMP_MAGIC
        if self.__le:
            fh = LEFileHdr(snaplen=snaplen, linktype=linktype, magic=magic)
            self._PktHdr = LEPktHdr()
        else:
            fh = FileHdr(snaplen=snaplen, linktype=linktype, magic=magic)
            self._PktHdr = PktHdr()

        self._pack_hdr = self._PktHdr._pack_hdr
        self.__f.write(bytes(fh))
    def writepkt(self, pkt, ts=None):
        if ts is None:
            ts = time.time()
        self.writepkt_time(bytes(pkt), ts)
    def writepkt_time(self, pkt, ts):
        n = len(pkt)
        sec = int(ts)
        usec = intround(ts % 1 * self._precision_multiplier)
        ph = self._pack_hdr(sec, usec, n, n)
        self.__f.write(ph + pkt)
    def writepkts(self, pkts):
        fd = self.__f
        pack_hdr = self._pack_hdr
        precision_multiplier = self._precision_multiplier

        for ts, pkt in pkts:
            n = len(pkt)
            sec = int(ts)
            usec = intround(ts % 1 * precision_multiplier)
            ph = pack_hdr(sec, usec, n, n)
            fd.write(ph + pkt)
    def close(self):
        self.__f.close()
