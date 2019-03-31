#!/usr/bin/python
"""
    Simple HTTP client for testing Trigger Interface.
    Requires: Python 2.4.2 or higher.
    Version: 0.1
"""
import time
import cgi
import xml.dom
from xml.dom import minidom, Node
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
import threading
from optparse import OptionParser
options = None  # global variable for storing cmd line options.

opt_parser = OptionParser()
opt_parser.add_option("-p", "--port", dest="soap_port", default = 30300,
                      help = "SOAP port number")

opt_parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default = False,
                      help = "verbose mode, printing Trigger messages")


class TriggerHandler(BaseHTTPRequestHandler):
    """
       HTTP POST handler
    """
    protocol_version = 'HTTP/1.1'
    global options
    def do_POST(self):
       self.path = "/DormantInterface/DormantInterfaceServlet"
       length = int(self.headers.getheader('content-length'))
       postvars = self.rfile.read(length)

       if options.verbose:
           print '\n### Trigger length:', length
           print '### Trigger message:'
           print postvars

       self.send_response(200)
       self.end_headers()
       return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main():
    global options
    try:
        (options, args) = opt_parser.parse_args()
        server = ThreadedHTTPServer(('', int(options.soap_port)), TriggerHandler)
        print "Serving HTTP at port %s..." % (options.soap_port)
        server.serve_forever()
    except KeyboardInterrupt:
        print "^C received, shutting down server"
        server.socket.close()


if __name__ == '__main__':
    main()

