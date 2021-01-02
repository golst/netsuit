
from netsuit.dpkt.dpkt import Packet
from netsuit.log import log_sys
import socket
import time
import contextlib
import sys
import resource
import errno

default_msg_size = resource.getpagesize()

NETLINK_ROUTE = 0  # Routing/device hook.
NETLINK_GENERIC = 16

NLM_F_REQUEST = 1  # It is request message.
NLM_F_MULTI = 2  # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK = 4  # Reply with ack, with zero or error code
NLM_F_ECHO = 8  # Echo this request
NLM_F_DUMP_INTR = 16  # Dump was inconsistent due to sequence change

# Modifiers to GET request.
NLM_F_ROOT = 0x100  # Specify tree root.
NLM_F_MATCH = 0x200  # Return all matching.
NLM_F_ATOMIC = 0x400  # Atomic GET.
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

# Modifiers to NEW request.
NLM_F_REPLACE = 0x100  # Override existing.
NLM_F_EXCL = 0x200  # Do not touch, if it exists.
NLM_F_CREATE = 0x400  # Create, if it does not exist.
NLM_F_APPEND = 0x800  # Add to end of list.


NL_SOCK_BUFSIZE_SET = 1 << 0
NL_SOCK_PASSCRED = 1 << 1
NL_OWN_PORT = 1 << 2
NL_MSG_PEEK = 1 << 3
NL_NO_AUTO_ACK = 1 << 4
NL_MSG_CRED_PRESENT = 1

NLMSG_ALIGNTO = 4
NLMSG_ALIGN = lambda len_: (len_ + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)
NLMSG_MIN_TYPE = 0x10
GENL_ID_CTRL = NLMSG_MIN_TYPE

CTRL_CMD_UNSPEC = 0
CTRL_CMD_NEWFAMILY = 1
CTRL_CMD_DELFAMILY = 2
CTRL_CMD_GETFAMILY = 3
CTRL_CMD_NEWOPS = 4
CTRL_CMD_DELOPS = 5
CTRL_CMD_GETOPS = 6
CTRL_CMD_NEWMCAST_GRP = 7
CTRL_CMD_DELMCAST_GRP = 8
CTRL_CMD_GETMCAST_GRP = 9  # Unused.
CTRL_CMD_MAX = CTRL_CMD_GETMCAST_GRP

CTRL_ATTR_UNSPEC = 0
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_VERSION = 3
CTRL_ATTR_HDRSIZE = 4
CTRL_ATTR_MAXATTR = 5
CTRL_ATTR_OPS = 6
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MAX = CTRL_ATTR_MCAST_GROUPS


CTRL_ATTR_OP_UNSPEC = 0
CTRL_ATTR_OP_ID = 1
CTRL_ATTR_OP_FLAGS = 2
CTRL_ATTR_OP_MAX = CTRL_ATTR_OP_FLAGS


CTRL_ATTR_MCAST_GRP_UNSPEC = 0
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2
CTRL_ATTR_MCAST_GRP_MAX = CTRL_ATTR_MCAST_GRP_ID

NLA_F_NESTED = 1 << 15
NLA_F_NET_BYTEORDER = 1 << 14
NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)


NLA_ALIGNTO = 4
NLA_ALIGN = lambda len_: (len_ + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)

class sockaddr_nl(Packet):
    __hdr__ = (
        ('nl_family','H',0),
        ('nl_pad','H',0),
        ('nl_pid','I',0),
        ('nl_groups','I',0)
    )
    __byte_order__ = '<' if sys.byteorder == 'little' else '>'


class nl_sock():
    def __init__(self):
        self.s_local = sockaddr_nl()
        self.s_peer = sockaddr_nl()
        self.s_proto = 0
        self.s_seq_next = 0
        self.s_seq_expect = 0
        self.s_flags = 0
        self.s_cb = None
        self.s_bufsize = None
        self.socket_instance = None
    def __repr__(self):
        """repr() handler."""
        answer_base = ("<{0}.{1} s_local='{2}' s_peer='{3}' s_fd={4} s_proto={5} s_seq_next={6} s_seq_expect={7} "
                       "s_flags={8} s_cb='{9}' s_bufsize={10}>")
        answer = answer_base.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.s_local, self.s_peer, self.s_fd, self.s_proto, self.s_seq_next, self.s_seq_expect, self.s_flags,
            self.s_cb, self.s_bufsize,
        )
        return answer
    @property
    def s_fd(self):
        try:
            return -1 if self.socket_instance is None else self.socket_instance.fileno()
        except socket.error:
            return -1

class nlmsghdr(Packet):
    __hdr__ = (
        ('nlmsg_len','I',0),
        ('nlmsg_type','H',0),
        ('nlmsg_flags','H',0),
        ('nlmsg_seq','I',0),
        ('nlmsg_pid','I',0)
    )
    __byte_order__ = '<' if sys.byteorder == 'little' else '>'

class genlmsghdr(Packet):
    __hdr__ = (
        ('cmd','B',0),
        ('version','B',0),
        ('reserved','H',0)
    )
    __byte_order__ = '<' if sys.byteorder == 'little' else '>'

class nlattr(Packet):
    __hdr__ = (
        ('nla_len','H',0),
        ('nla_type','H',0)
    )
    __byte_order__ = '<' if sys.byteorder == 'little' else '>'

NLA_HDRLEN = NLA_ALIGN(nlattr.__hdr_len__)

GENL_HDRLEN = NLMSG_ALIGN(genlmsghdr.__hdr_len__)
GENL_HDRSIZE = lambda hdrlen: GENL_HDRLEN + hdrlen 

NLMSG_HDRLEN = NLMSG_ALIGN(nlmsghdr.__hdr_len__)
NLMSG_LENGTH = lambda len_: len_ + NLMSG_ALIGN(NLMSG_HDRLEN)
NLMSG_SPACE = lambda len_: NLMSG_ALIGN(NLMSG_LENGTH(len_))

class nl_cb(object):
    """
    Instance variables:
    cb_set -- dictionary of callback functions (values), indexed by callback type (keys).
    cb_args -- dictionary of arguments to be passed to callback functions (values), indexed by callback type (keys).
    cb_err -- error callback function.
    cb_err_arg -- argument to be passed to error callback function.
    cb_recvmsgs_ow -- call this function instead of recvmsgs() in nl_recvmsgs_report(). Args are (sk, cb).
    cb_recv_ow -- call this function instead of nl_recv() in recvmsgs(). Args are (sk, nla, buf, creds).
    cb_send_ow -- call this function instead of nl_send_iovec() in nl_send(). Args are (sk, msg).
    cb_active -- current callback type (e.g. NL_CB_MSG_OUT). Modified before every callback function call.
    """
    def __init__(self):
        self.cb_set = dict()
        self.cb_args = dict()
        self.cb_err = None
        self.cb_err_arg = None
        self.cb_recvmsgs_ow = None
        self.cb_recv_ow = None
        self.cb_send_ow = None
        self.cb_active = None

def generate_local_port():
    port = 0
    with contextlib.closing(socket.socket(socket.AF_NETLINK,socket.SOCK_RAW)) as s:
        s.bind((0,0))
        port = s.getsockname()[0]
        port = int(port)
    return port

def nl_socket_get_local_port(sk):

    if not sk.s_local.nl_pid:
        port = generate_local_port()
        sk.s_flags &= ~NL_OWN_PORT
        sk.s_local.nl_pid = port
        return port
    return sk.s_local.nl_pid


def nl_socket_alloc(cb=None):
    cb = cb or nl_cb()
    sk = nl_sock()
    sk.s_cb = cb
    sk.s_local.nl_family = socket.AF_NETLINK
    sk.s_peer.nl_family = socket.AF_NETLINK
    sk.s_seq_expect = sk.s_seq_next = int(time.time())
    nl_socket_get_local_port(sk)
    return sk

def nl_socket_set_buffer_size(sk, rxbuf, txbuf):
    rxbuf = 32768 if rxbuf <= 0 else rxbuf
    txbuf = 32768 if txbuf <= 0 else txbuf
    if sk.s_fd == -1:
        log_sys.critical("none socket ")
        return -1

    try:
        sk.socket_instance.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, txbuf)
    except OSError as exc:
        log_sys.critical("socket setsocketopt error %s" % exc)
        return -1

    try:
        sk.socket_instance.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rxbuf)
    except OSError as exc:
        log_sys.critical("socket setsocketopt error %s" % exc)
        return -1

    sk.s_flags |= NL_SOCK_BUFSIZE_SET
    return 0

def nl_connect(sk,protocol):
    flag  = getattr(socket,'SOCK_CLOEXEC',0)
    if sk.s_fd != -1:
        log_sys.critical("netlink bad socket")
        return -1
    try:
        sk.socket_instance = socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|flag,protocol)
    except OSError as exc:
        log_sys.critical("create socket error %s" % exc)

    if not sk.s_flags & NL_SOCK_BUFSIZE_SET:
        err = nl_socket_set_buffer_size(sk, 0, 0)
        if err < 0:
            sk.socket_instance.close()
            return err
    try:
        sk.socket_instance.bind((sk.s_local.nl_pid, sk.s_local.nl_groups))
    except OSError as exc:
        sk.socket_instance.close()
        log_sys.critical("netlink socket bind error %s" % exc)
        return -1
    sk.s_local.nl_pid = sk.socket_instance.getsockname()[0]

    if sk.s_local.nl_family != socket.AF_NETLINK:
        sk.socket_instance.close()
        log_sys.critical("netlink sock addr error")
        return -1

    sk.s_proto = protocol
    return 0  

def nlmsg_size(payload):
    return int(NLMSG_HDRLEN + payload)
def nla_attr_size(payload):
    return int(NLA_HDRLEN + payload)

def nla_total_size(payload):
    return int(NLA_ALIGN(nla_attr_size(payload)))

def nla_reserve(msg,attrlen):
    tlen = NLMSG_ALIGN(msg.nlmsg_len) + nla_total_size(attrlen)
    return tlen

class GenericSock():
    def __init__(self,default_len = default_msg_size):
        self.msg_len = default_msg_size
        self.sk = nl_socket_alloc()
        ret = nl_connect(self.sk,NETLINK_GENERIC)
        if ret < 0:
            log_sys.critical("genl socket create error")
        self.nlmsg = nlmsghdr(b'\x00'*self.msg_len)
        self.nlmsg.nlmsg_len = nlmsg_size(0)
        self.genlmsg = genlmsghdr()

    def genl_ctrl_resolve(self,name):
        self.family = name
        self.genlmsg.cmd = CTRL_CMD_GETFAMILY
        self.genlmsg.version = 1
        self.nlmsg.nlmsg_pid = nl_socket_get_local_port(self.sk)
        self.nlmsg.nlmsg_seq = self.sk.s_seq_next
        self.sk.s_seq_next += 1
        self.nlmsg.nlmsg_type = GENL_ID_CTRL
        self.nlmsg.nlmsg_flags = 0
        self.nlmsg.data[:GENL_HDRLEN] = bytes(self.genlmsg)[:]
        self.nlmsg.nlmsg_len += GENL_HDRLEN
        self.pos_data = GENL_HDRLEN
        str_name = bytearray(name) + bytearray(b'\0')
        nla_tmp = nlattr()
        nla_tmp.nla_len = nla_attr_size(len(str_name))
        nla_tmp.nla_type = CTRL_ATTR_FAMILY_NAME
        nla_tmp.data = str_name
        tmp_len = nla_total_size(len(str_name))
        self.nlmsg.nlmsg_len += tmp_len
        self.nlmsg.data[self.pos_data:self.pos_data + tmp_len] = bytes(nla_tmp)
        self.nlmsg.nlmsg_flags |= NLM_F_REQUEST
        self.nlmsg.nlmsg_flags |= NLM_F_ACK
        self.iov = bytes(self.nlmsg)[:self.nlmsg.nlmsg_len]
        ret = self.sk.socket_instance.send(self.iov,0)
        recv_buf = bytearray()
        while True:
            try:
                iov,_,msg_flags,address = self.sk.socket_instance.recvmsg(self.msg_len,0,0)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                log_sys.critical("recvmsg error")
                return
            if not iov:
                log_sys.critical("recvmsg no data")
                return
            if msg_flags & socket.MSG_CTRUNC:
                raise NotImplementedError
            if self.msg_len < len(iov) or msg_flags & socket.MSG_TRUNC:
                self.msg_len = len(iov)
                continue
            if iov:
                recv_buf += iov
            break
        print('--------------------')
        print(recv_buf)
        print('----------------------')
    def close(self):
        if self.sk and self.sk.socket_instance and self.sk.s_fd != -1:
            self.sk.socket_instance.close()
