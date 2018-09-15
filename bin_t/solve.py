from pybst import avltree as avl
from pwn import *

HOST = 'misc.chal.csaw.io'
PORT = '9001'

r = remote(HOST, PORT)

m = r.recvuntil('Send the preorder traversal in a comma sperated list.')
print m
m = m.split('\r')[1].strip()
stuff = m.split(',')
seq = [(int(i), True) for i in stuff]
tree = avl.AVLTree(seq)
ans = []
for i in tree.preorder():
	ans.append(str(i.key))
hi = ','.join(ans)
r.sendline(hi)
try:
	while True:
		print r.recv().strip(),
except:
	pass
