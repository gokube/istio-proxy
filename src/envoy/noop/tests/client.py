import httplib
import urllib2

KEYFILE="../certs/cert.key"
CLIENT_CERT_FILE="../certs/client.crt"

# HTTPS Client Auth solution for urllib2, inspired by
# http://bugs.python.org/issue3466
# and improved by David Norton of Three Pillar Software. In this
# implementation, we use properties passed in rather than static module
# fields.
class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key, cert):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert
    def https_open(self, req):
        #Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        return self.do_open(self.getConnection, req)
    def getConnection(self, host, timeout):
        return httplib.HTTPSConnection(host, key_file=self.key, cert_file=self.cert)


cert_handler = HTTPSClientAuthHandler(KEYFILE, CLIENT_CERT_FILE)
opener = urllib2.build_opener(cert_handler)
urllib2.install_opener(opener)

f = urllib2.urlopen("https://server.test.com:9090/")
print f.code
