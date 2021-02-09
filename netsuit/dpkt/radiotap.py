
import socket

from netsuit.dpkt import dpkt
from netsuit.dpkt import ieee80211

# Ref: http://www.radiotap.org
# Fields Ref: http://www.radiotap.org/defined-fields/all

# Present flags
_TSFT_MASK = 0x1000000
_FLAGS_MASK = 0x2000000
_RATE_MASK = 0x4000000
_CHANNEL_MASK = 0x8000000
_FHSS_MASK = 0x10000000
_ANT_SIG_MASK = 0x20000000
_ANT_NOISE_MASK = 0x40000000
_LOCK_QUAL_MASK = 0x80000000
_TX_ATTN_MASK = 0x10000
_DB_TX_ATTN_MASK = 0x20000
_DBM_TX_POWER_MASK = 0x40000
_ANTENNA_MASK = 0x80000
_DB_ANT_SIG_MASK = 0x100000
_DB_ANT_NOISE_MASK = 0x200000
_RX_FLAGS_MASK = 0x400000
_CHANNELPLUS_MASK = 0x200
_EXT_MASK = 0x80

_TSFT_SHIFT = 24
_FLAGS_SHIFT = 25
_RATE_SHIFT = 26
_CHANNEL_SHIFT = 27
_FHSS_SHIFT = 28
_ANT_SIG_SHIFT = 29
_ANT_NOISE_SHIFT = 30
_LOCK_QUAL_SHIFT = 31
_TX_ATTN_SHIFT = 16
_DB_TX_ATTN_SHIFT = 17
_DBM_TX_POWER_SHIFT = 18
_ANTENNA_SHIFT = 19
_DB_ANT_SIG_SHIFT = 20
_DB_ANT_NOISE_SHIFT = 21
_RX_FLAGS_SHIFT = 22
_CHANNELPLUS_SHIFT = 10
_EXT_SHIFT = 7

# Flags elements
_FLAGS_SIZE = 2
_CFP_FLAG_SHIFT = 0
_PREAMBLE_SHIFT = 1
_WEP_SHIFT = 2
_FRAG_SHIFT = 3
_FCS_SHIFT = 4
_DATA_PAD_SHIFT = 5
_BAD_FCS_SHIFT = 6
_SHORT_GI_SHIFT = 7

# Channel type
_CHAN_TYPE_SIZE = 4
_CHANNEL_TYPE_SHIFT = 4
_CCK_SHIFT = 5
_OFDM_SHIFT = 6
_TWO_GHZ_SHIFT = 7
_FIVE_GHZ_SHIFT = 8
_PASSIVE_SHIFT = 9
_DYN_CCK_OFDM_SHIFT = 10
_GFSK_SHIFT = 11
_GSM_SHIFT = 12
_STATIC_TURBO_SHIFT = 13
_HALF_RATE_SHIFT = 14
_QUARTER_RATE_SHIFT = 15

# Flags offsets and masks
_FCS_SHIFT = 4
_FCS_MASK = 0x10


class Radiotap(dpkt.Packet):
    """Radiotap.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Radiotap.
        TODO.
    """

    __hdr__ = (
        ('version', 'B', 0),
        ('pad', 'B', 0),
        ('length', 'H', 0),
        ('present_flags', 'I', 0)
    )
    # __byte_order__ = '<'

    @property
    def tsft_present(self):
        return (self.present_flags & _TSFT_MASK) >> _TSFT_SHIFT

    @tsft_present.setter
    def tsft_present(self, val):
        self.present_flags |= val << _TSFT_SHIFT

    @property
    def flags_present(self):
        return (self.present_flags & _FLAGS_MASK) >> _FLAGS_SHIFT

    @flags_present.setter
    def flags_present(self, val):
        self.present_flags |= val << _FLAGS_SHIFT

    @property
    def rate_present(self):
        return (self.present_flags & _RATE_MASK) >> _RATE_SHIFT

    @rate_present.setter
    def rate_present(self, val):
        self.present_flags |= val << _RATE_SHIFT

    @property
    def channel_present(self):
        return (self.present_flags & _CHANNEL_MASK) >> _CHANNEL_SHIFT

    @channel_present.setter
    def channel_present(self, val):
        self.present_flags |= val << _CHANNEL_SHIFT

    @property
    def fhss_present(self):
        return (self.present_flags & _FHSS_MASK) >> _FHSS_SHIFT

    @fhss_present.setter
    def fhss_present(self, val):
        self.present_flags |= val << _FHSS_SHIFT

    @property
    def ant_sig_present(self):
        return (self.present_flags & _ANT_SIG_MASK) >> _ANT_SIG_SHIFT

    @ant_sig_present.setter
    def ant_sig_present(self, val):
        self.present_flags |= val << _ANT_SIG_SHIFT

    @property
    def ant_noise_present(self):
        return (self.present_flags & _ANT_NOISE_MASK) >> _ANT_NOISE_SHIFT

    @ant_noise_present.setter
    def ant_noise_present(self, val):
        self.present_flags |= val << _ANT_NOISE_SHIFT

    @property
    def lock_qual_present(self):
        return (self.present_flags & _LOCK_QUAL_MASK) >> _LOCK_QUAL_SHIFT

    @lock_qual_present.setter
    def lock_qual_present(self, val):
        self.present_flags |= val << _LOCK_QUAL_SHIFT

    @property
    def tx_attn_present(self):
        return (self.present_flags & _TX_ATTN_MASK) >> _TX_ATTN_SHIFT

    @tx_attn_present.setter
    def tx_attn_present(self, val):
        self.present_flags |= val << _TX_ATTN_SHIFT

    @property
    def db_tx_attn_present(self):
        return (self.present_flags & _DB_TX_ATTN_MASK) >> _DB_TX_ATTN_SHIFT

    @db_tx_attn_present.setter
    def db_tx_attn_present(self, val):
        self.present_flags |= val << _DB_TX_ATTN_SHIFT

    @property
    def dbm_tx_power_present(self):
        return (self.present_flags & _DBM_TX_POWER_MASK) >> _DBM_TX_POWER_SHIFT

    @dbm_tx_power_present.setter
    def dbm_tx_power_present(self, val):
        self.present_flags |= val << _DBM_TX_POWER_SHIFT

    @property
    def ant_present(self):
        return (self.present_flags & _ANTENNA_MASK) >> _ANTENNA_SHIFT

    @ant_present.setter
    def ant_present(self, val):
        self.present_flags |= val << _ANTENNA_SHIFT

    @property
    def db_ant_sig_present(self):
        return (self.present_flags & _DB_ANT_SIG_MASK) >> _DB_ANT_SIG_SHIFT

    @db_ant_sig_present.setter
    def db_ant_sig_present(self, val):
        self.present_flags |= val << _DB_ANT_SIG_SHIFT

    @property
    def db_ant_noise_present(self):
        return (self.present_flags & _DB_ANT_NOISE_MASK) >> _DB_ANT_NOISE_SHIFT

    @db_ant_noise_present.setter
    def db_ant_noise_present(self, val):
        self.present_flags |= val << _DB_ANT_NOISE_SHIFT

    @property
    def rx_flags_present(self):
        return (self.present_flags & _RX_FLAGS_MASK) >> _RX_FLAGS_SHIFT

    @rx_flags_present.setter
    def rx_flags_present(self, val):
        self.present_flags |= val << _RX_FLAGS_SHIFT

    @property
    def chanplus_present(self):
        return (self.present_flags & _CHANNELPLUS_MASK) >> _CHANNELPLUS_SHIFT

    @chanplus_present.setter
    def chanplus_present(self, val):
        self.present_flags |= val << _CHANNELPLUS_SHIFT

    @property
    def ext_present(self):
        return (self.present_flags & _EXT_MASK) >> _EXT_SHIFT

    @ext_present.setter
    def ext_present(self, val):
        self.present_flags |= val << _EXT_SHIFT

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = buf[socket.ntohs(self.length):]
        self.fields = []
        buf = buf[self.__hdr_len__:]

        # decode each field into self.<name> (eg. self.tsft) as well as append it self.fields list
        field_decoder = [
            ('tsft', self.tsft_present, self.TSFT),
            ('flags', self.flags_present, self.Flags),
            ('rate', self.rate_present, self.Rate),
            ('channel', self.channel_present, self.Channel),
            ('fhss', self.fhss_present, self.FHSS),
            ('ant_sig', self.ant_sig_present, self.AntennaSignal),
            ('ant_noise', self.ant_noise_present, self.AntennaNoise),
            ('lock_qual', self.lock_qual_present, self.LockQuality),
            ('tx_attn', self.tx_attn_present, self.TxAttenuation),
            ('db_tx_attn', self.db_tx_attn_present, self.DbTxAttenuation),
            ('dbm_tx_power', self.dbm_tx_power_present, self.DbmTxPower),
            ('ant', self.ant_present, self.Antenna),
            ('db_ant_sig', self.db_ant_sig_present, self.DbAntennaSignal),
            ('db_ant_noise', self.db_ant_noise_present, self.DbAntennaNoise),
            ('rx_flags', self.rx_flags_present, self.RxFlags)
        ]
        if self.ext_present == 1:
            buf = buf[4:]
        buf = buf[4:]
        for name, present_bit, parser in field_decoder:
            if present_bit:
                field = parser(buf)
                field.data = b''
                setattr(self, name, field)
                self.fields.append(field)
                buf = buf[len(field):]

        if len(self.data) > 0:
            if self.flags_present and self.flags.fcs:
                self.data = ieee80211.IEEE80211(self.data, fcs=self.flags.fcs)
            else:
                self.data = ieee80211.IEEE80211(self.data)

    class Antenna(dpkt.Packet):
        __hdr__ = (
            ('index', 'B', 0),
        )

    class AntennaNoise(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class AntennaSignal(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class Channel(dpkt.Packet):
        __hdr__ = (
            ('freq', 'H', 0),
            ('flags', 'H', 0),
        )
        __byte_order__ = '<'

    class FHSS(dpkt.Packet):
        __hdr__ = (
            ('set', 'B', 0),
            ('pattern', 'B', 0),
        )

    class Flags(dpkt.Packet):
        __hdr__ = (
            ('val', 'B', 0),
        )

        @property
        def fcs(self): return (self.val & _FCS_MASK) >> _FCS_SHIFT

        # TODO statement seems to have no effect
        @fcs.setter
        def fcs(self, v): (v << _FCS_SHIFT) | (self.val & ~_FCS_MASK)


    class LockQuality(dpkt.Packet):
        __hdr__ = (
            ('val', 'H', 0),
        )

    class RxFlags(dpkt.Packet):
        __hdr__ = (
            ('val', 'H', 0),
        )

    class Rate(dpkt.Packet):
        __hdr__ = (
            ('val', 'B', 0),
        )

    class TSFT(dpkt.Packet):
        __hdr__ = (
            ('usecs', 'Q', 0),
        )
        __byte_order__ = '<'

    class TxAttenuation(dpkt.Packet):
        __hdr__ = (
            ('val', 'H', 0),
        )

    class DbTxAttenuation(dpkt.Packet):
        __hdr__ = (
            ('db', 'H', 0),
        )

    class DbAntennaNoise(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbAntennaSignal(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbmTxPower(dpkt.Packet):
        __hdr__ = (
            ('dbm', 'B', 0),
        )

