from stem import Signal
from stem.control import Controller
import requests
import win_inet_pton
from config import CONFIG
# signal TOR for a new connection 
def renew_connection():
    with Controller.from_port(port = 9151) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

    	bytes_read = controller.get_info("traffic/read")
    	bytes_written = controller.get_info("traffic/written")
    	print "My Tor realy has read %s bytes and written %s" % (bytes_read, bytes_written)


req = requests.get('http://icanhazip.com/', 
proxies=CONFIG['ONLINE']['PROXIES'],
verify=(not CONFIG['ONLINE']['MITMPROXY']))
print req.content
renew_connection()
req = requests.get('http://icanhazip.com/', 
proxies=CONFIG['ONLINE']['PROXIES'],
verify=(not CONFIG['ONLINE']['MITMPROXY']))
print req.content
