#!/usr/bin/python

from pwn import *

HOST = 'rev.chal.csaw.io'
PORT = '9003'

r = remote(HOST, PORT)
p = log.progress('Current Status')
p.status('Waiting for Response')

answer = '0x00'
print r.recvuntil('What ') + r.recv().strip()
log.info('Answer: {}'.format(answer))
r.sendline(answer)
p.status('Question 1 Completed!')

answer = '0x00'
print r.recvuntil('What ') + r.recv().strip()
log.info('Answer: {}'.format(answer))
r.sendline(answer)
p.status('Question 2 Completed!')

answer = '0x0000'
print r.recvuntil('What ') + r.recv().strip()
log.info('Answer: {}'.format(answer))
r.sendline(answer)
p.status('Question 3 Completed!')

answer = '0x0e74'
print r.recvuntil('What ') + r.recv().strip()
log.info('Answer: {}'.format(answer))
r.sendline(answer)
p.status('Question 4 Completed!')

answer = '0x0e61'
print r.recvuntil('What ') + r.recv().strip()
log.info('Answer: {}'.format(answer))
r.sendline(answer)
p.status('Question 5 Completed!')

print r.recv().strip()
p.success('Flag obtained!')
