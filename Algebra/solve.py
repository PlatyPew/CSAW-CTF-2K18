from pwn import *
import time
from sympy.solvers import solve
from sympy import Symbol
r = remote('misc.chal.csaw.io','9002')
m = r.recv(1000)
print m
m = r.recv(1000)
x = Symbol('X')
print m
k=m.split('\n')[0]
kk=k.split("=")
print kk
k=kk[0]+" - "+kk[1]
print k
l=solve(k, x)
print str(float(l[0]))
r.sendline(str(float(l[0])))
k = r.recv(1000)
print k
time.sleep(1)
while True:
	k=k.split('\n')[1]
	kk=k.split("=")
	#print kk
	k=kk[0]+" - "+kk[1]
	#print k
        l=solve(k, x)
	print l
        print str(float(l[0]))
	r.sendline(str(float(l[0])))
        k = r.recv(1000)
        print k
        time.sleep(1)

		