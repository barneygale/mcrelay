import struct
from twisted.internet import protocol, reactor, task

##
## Buffer type
##
import time


class Underrun(Exception):
    pass

class Buffer(object):
    def __init__(self):
        self.buff1 = ""
        self.buff2 = ""

    def length(self):
        return len(self.buff1)

    def empty(self):
        return len(self.buff1) == 0

    def add(self, d):
        self.buff1 += d
        self.buff2 = self.buff1

    def restore(self):
        self.buff1 = self.buff2

    def peek(self):
        if len(self.buff1) < 1:
            raise Underrun()
        return ord(self.buff1[0])

    def unpack_raw(self, l):
        if len(self.buff1) < l:
            raise Underrun()
        d, self.buff1 = self.buff1[:l], self.buff1[l:]
        return d

    def unpack(self, ty):
        s = struct.unpack('>'+ty, self.unpack_raw(struct.calcsize(ty)))
        return s[0] if len(ty) == 1 else s

    def unpack_string(self):
        l = self.unpack('h')
        return self.unpack_raw(l*2).decode('utf-16be')

    def unpack_array(self):
        l = self.unpack('h')
        return self.unpack_raw(l)

##
## Throttle logic
##

class Throttle(object):
    def __init__(self, timeout):
        self.timeout = timeout
        self.throttled = {}
        t = task.LoopingCall(self.clean)
        t.start(3600)
    def get(self, ip):
        ex = self.throttled.get(ip, None)
        if not ex is None:
            d = ex-int(time.time())
            if d > 0:
                return d
        self.throttled[ip] = int(time.time()) + self.timeout
        return 0
    def clean(self):
        t = int(time.time())
        for k, v in dict(self.throttled).iteritems():
            if v > t:
                del self.throttled[k]

##
## Handlers for different protocol versions
##

protocol_handlers = dict()
def handles(*v):
    def inner(cls):
        for v0 in v:
            protocol_handlers[v0] = cls
        return cls
    return inner


class ProtocolHandler(object):
    def __init__(self, handle_handshake=None, handle_auth=None, handle_ping=None):
        self.handle_handshake = handle_handshake
        self.handle_auth = handle_auth
        self.handle_ping = handle_ping
        self.setup()
    def setup(self):
        pass
    def handle_client(self, ident, buff):
        raise NotImplementedError
    def handle_server(self, ident, buff):
        raise NotImplementedError
    def handle_server_dc(self):
        pass
    def handle_client_dc(self):
        pass

class PingHandler(ProtocolHandler):
    def handle_client(self, ident, buff):
        if ident == 0xFE:
            buff.unpack('B')
            self.handle_ping()
        else:
            raise NotImplementedError
    def handle_server(self, ident, buff):
        if ident == 0xFF:
            buff.unpack_string()
        else:
            raise NotImplementedError


@handles(51, 60) #1.4 ... 13w09c
class ProtocolHandler51(ProtocolHandler):
    def setup(self):
        self.stage = 0
    def handle_client(self, ident, buff):
        if self.stage == 0:
            if ident == 0x02:
                buff.unpack('B')     #protocol version
                self.username = str(buff.unpack_string())
                buff.unpack_string() #host
                buff.unpack('i')     #port

                self.handle_handshake(self.username)
            elif ident == 0xFC:
                buff.unpack_array()  #shared secret
                buff.unpack_array()  #verify token
            else:
                raise NotImplementedError
        elif self.stage == 1:
            self.stage = 2
        elif self.stage == 2:
            pass
        elif self.stage == 3:
            self.handle_auth(self.username, True)
        else:
            raise NotImplementedError

    def handle_server(self, ident, buff):
        if self.stage == 0:
            if ident == 0xFC:
                buff.unpack_array()  #empty
                buff.unpack_array()  #empty

                self.stage = 1
            elif ident == 0xFD:
                buff.unpack_string() #server id
                buff.unpack_array()  #public key
                buff.unpack_array()  #verify token
            else:
                raise NotImplementedError
        elif self.stage == 2:
            self.stage = 3
        elif self.stage == 3:
            pass
        else:
            raise NotImplementedError

    def handle_server_dc(self):
        if self.stage == 3:
            self.stage = 4
            self.handle_auth(self.username, False)


class ServerProtocol(protocol.Protocol):
    def __init__(self, factory, addr):
        self.factory = factory
        self.addr = addr

        self.buff = Buffer()
        self.handler = None
        self.proxy_protocol = None
        self.proxy_send_queue = ""

    def dataReceived(self, data):
        self.buff.add(data)
        try:
            ident = self.buff.unpack('B')
            if not self.handler:
                if ident == 0x02:
                    version = self.buff.peek()
                    self.handler = protocol_handlers[version](self.handle_handshake, self.handle_auth)
                elif ident == 0xFE:
                    self.handler = PingHandler(handle_ping = self.handle_ping)
                else:
                    raise NotImplementedError

            self.handler.handle_client(ident, self.buff)
        except Underrun:
            self.buff.restore()

        if self.proxy_protocol:
            self.proxy_protocol.transport.write(data)
        else:
            self.proxy_send_queue += data

    def connectionLost(self, reason=None):
        if self.handler:
            self.handler.handle_server_dc()
        if self.proxy_protocol:
            self.proxy_protocol.transport.loseConnection()

    def handle_ping(self):
        self.factory.handle_ping(self, self.addr.host)

    def handle_handshake(self, username):
        self.factory.handle_handshake(self, self.addr.host, username)

    def handle_auth(self, username, result):
        if result: #switch to pass-through
            self.dataReceived = self.proxy_protocol.transport.write
            self.proxy_protocol.dataReceived = self.transport.write
        self.factory.handle_auth(self, self.addr.host, username, result)

    def kick(self, msg):
        self.transport.write('\xff' + struct.pack('>h', len(msg)) + msg.encode('utf-16be'))
        self.transport.loseConnection()

    def proxy_connect(self):
        f = protocol.ClientFactory()
        f.buildProtocol = lambda a: ClientProtocol(self, a)
        reactor.connectTCP(self.factory.c_addr[0], self.factory.c_addr[1], f)

    def proxy_connected(self, protocol):
        self.proxy_protocol = protocol
        protocol.transport.write(self.proxy_send_queue)
        self.proxy_send_queue = ""

    def proxy_disconnected(self, protocol):
        if self.handler:
            self.handler.handle_client_dc()
        self.transport.loseConnection()


class ClientProtocol(protocol.Protocol):
    def __init__(self, server, addr):
        self.server = server
        self.addr = addr
        self.buff = Buffer()

    def connectionMade(self):
        self.server.proxy_connected(self)

    def connectionLost(self, reason=None):
        self.server.proxy_disconnected(self)

    def dataReceived(self, data):
        self.buff.add(data)
        try:
            ident = self.buff.unpack('B')
            self.server.handler.handle_server(ident, self.buff)
        except Underrun:
            self.buff.restore()

        self.server.transport.write(data)


class MCRelay(protocol.ServerFactory):
    def __init__(self, s_addr, c_addr, throttle_time=5):
        self.s_addr = s_addr
        self.c_addr = c_addr

        self.throttle = Throttle(throttle_time)
        self.setup()

    def buildProtocol(self, addr):
        return ServerProtocol(self, addr)

    def run(self):
        reactor.listenTCP(self.s_addr[1], self, interface=self.s_addr[0])
        reactor.run()

    def throttled(self, proto, ip):
        th = self.throttle.get(ip)
        if th > 0:
            proto.kick("Throttled! Please wait %d second%s." % (th, 's' if th>1 else ''))
            return True
        return False

    def setup(self):
        pass

    def handle_ping(self, proto, ip):
        proto.proxy_connect()

    def handle_handshake(self, proto, ip, username):
        if not self.throttled(proto, ip):
            proto.proxy_connect()

    def handle_auth(self, proto, ip, username, result):
        pass
