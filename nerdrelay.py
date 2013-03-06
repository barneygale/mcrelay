import json
from twisted.web.client import getPage
from mcrelay import MCRelay

API_URL = 'http://mcbouncer.com/api'
API_KEY = ''

class MCBouncer:
    def __getattr__(self, name):
        def inner(*args):
            def error(e):
                print "%s(%s): %s" % (name, ', '.join(args), e.getErrorMessage())
            d = getPage('/'.join([API_URL, name, API_KEY] + list(args)), timeout=5)
            d.addErrback(error)
            return d
        return inner

class NerdRelay(MCRelay):
    def setup(self):
        self.bouncer = MCBouncer()

    def handle_handshake(self, proto, ip, username):
        if not self.throttled(proto, ip):
            def callback(data):
                try:
                    data = json.loads(data)
                except:
                    proto.kick("Protocol error")
                    return
                if data['is_banned']:
                    proto.kick(data['reason'])
                else:
                    proto.proxy_connect()
            d = self.bouncer.getIPBanReason(ip)
            d.addCallback(callback)

    def handle_auth(self, proto, ip, username, result):
        if result:
            self.bouncer.updateUser(username, ip)


if __name__ == '__main__':
    import sys
    args = sys.argv[1:]
    if len(args) != 4:
        print "usage: python nerdrelay.py listenHOST listenPORT connectHOST connectPORT"
    else:
        s_addr = (args[0], int(args[1]))
        c_addr = (args[2], int(args[3]))
        p = NerdRelay(s_addr, c_addr)
        p.run()