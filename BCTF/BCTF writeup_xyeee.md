## 签到题

### Freenode weechat

![微信截图_20181127141140.png](https://i.loli.net/2018/12/18/5c18972ff3f41.png)



### guess_polynomial

只要你输入的p够大，就可以将多项式转化为p进制

解题脚本如下

```python
#-*- coding: utf-8 -*-
import socket
import time
import re

HOST = '39.96.8.114'
PORT = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

X = 1329227995784915872903807060280345027

def send(a):
    a = a + '\n'
    sock.send(a.encode())

def decode(m):
    m = int(m)
    a = []
    e = ''
    i = 0
    r = 1329227995784915872903807060280345027
    while True:
        a.append(m % r)
        tmp = str(a[i])
        e = tmp + ' ' + e
        if m < r:
            break
        m = m - a[i]
        m = m // r
        i = i+1
    # print (a)
    # import pdb;pdb.set_trace()
    return e

def calc(coeff, x):
    num = coeff[0]
    for i in range(1, len(coeff)):
        num = num * x + coeff[i]
    return num

for i in range(10):
    send(str(X))
    time.sleep(1)
    response = sock.recv(5000)
    response = response.decode('utf-8')
    sum = re.findall(r'(\w*[0-9]+)\w*',response)[0]
    print ('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>sum = ' + sum)
    send(decode(sum))
    time.sleep(0.1)
    response = sock.recv(1024)
    response = response.decode('utf-8')
    print ('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<' + response)

sock.close()
```



运行结果如下

![微信截图_20181127175445.png](https://i.loli.net/2018/12/18/5c1896e96bd2b.png)