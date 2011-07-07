#!/usr/bin/python

"""Minimal non-feature complete socks proxy"""

import logging
from logging import error, info, debug
import random
import socket
from SocketServer import StreamRequestHandler, ThreadingTCPServer
from struct import pack, unpack
import threading

class MyTCPServer(ThreadingTCPServer):
    allow_reuse_address = True
CLOSE = object()

logging.basicConfig(filename='/dev/stderr', level=logging.DEBUG)

VERSION = '\x05'
NOAUTH = '\x00'
CONNECT = '\x01'
IPV4 = '\x01'
DOMAIN_NAME = '\x03'
SUCCESS = '\x00'

def send(dest, msg):
    if msg == CLOSE:
        dest.close()
        return 0
    else:
        return dest.send(msg)
def recv(source, buffer):
    data = source.recv(buffer)
    if data == '':
        return CLOSE
    else:
        return data

def forward(source, dest, name):
    while True:
        data = recv(source, 4000)
        if data == '':
            send(dest, CLOSE)
            info('%s hung up' % name)
            return
        debug('Sending %r' % (data,))
        send(dest, data)

def spawn_forwarder(source, dest, name):
    t = threading.Thread(target=forward, args=(source, dest, name))
    t.daemon = True
    t.start()

class SocksHandler(StreamRequestHandler):
    """Highly feature incomplete SOCKS 5 implementation"""

    def close_request(self):
        self.server.close_request(self.request)

    def read(self, n):
        data = ''
        while len(data) < n:
            extra = self.rfile.read(n)
            if extra == '':
                raise Exception('Connection closed')
            data += extra
        return data

    def handle(self):
        # IMRPOVEMENT: Report who requests are from in logging
        # IMPROVEMENT: Timeout on client
        info('Connection - authenticating')
        version = self.read(1)

        if version != '\x05':
            error('Wrong version number (%r) closing...' % version)
            self.close_request()
            return

        nmethods = ord(self.read(1))
        method_list = self.read(nmethods)

        if NOAUTH not in method_list:
            error('Server only supports NOAUTH')
            self.send_no_method()
            return
        else:
            self.send_no_auth_method()
            info('Authenticated')

        # If we were authenticating it would go here
        version, cmd, zero, address_type = self.read(4)
        if version != '\x05':
            error('Wrong version number (%r) closing...' % version)
            self.close_request()
        elif cmd != CONNECT:
            error('Only supports connect method not (%r) closing' % cmd)
            self.close_request()
        elif zero != '\x00':
            error('Mangled request. Reserved field (%r) is not null' % zero)
            self.close_request()

        if address_type == 'IPV4':
            raw_dest_address = self.read(4)
            dest_address = '.'.join(map(str, unpack('>4B', raw_dest_address)))
        elif address_type == DOMAIN_NAME:
            dns_length = ord(self.read(1))
            dns_name = self.read(dns_length)
            dest_address = dns_name
        else:
            error('Only supports IPV4 addressing not (%r)' % address_type)
            self.close_request()

        raw_dest_port = self.read(2)
        dest_port, = unpack('>H', raw_dest_port)

        outbound_sock = socket.socket()
        out_address = (dest_address, dest_port)
        debug("Creating forwarder connection to %r", out_address)
        outbound_sock.connect(out_address)

        self.send_reply(outbound_sock.getsockname())
    
        spawn_forwarder(outbound_sock, self.request, 'destination')
        forward(self.request, outbound_sock, 'client')

    def send_reply(self, (bind_addr, bind_port)):
        bind_tuple = tuple(map(int, bind_addr.split('.')))
        full_address = bind_tuple + (bind_port,)
        info('Setting up forwarding port %r' % (full_address,))
        msg = pack('>cccc4BH', VERSION, SUCCESS, '\x00', IPV4, *full_address)
        self.wfile.write(msg)

    def send_no_method(self):
        self.wfile.write('\x05\xff')
        self.close_request()

    def send_no_auth_method(self):
        self.wfile.write('\x05\x00')
        self.wfile.flush()

if __name__ == '__main__':
    info('Listening on port 8002...')
    server = MyTCPServer(('localhost', 8002), SocksHandler)
    server.serve_forever()
