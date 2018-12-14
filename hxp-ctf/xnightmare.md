---
title: wp-hxp_ctf
date: 2018-12-07 21:00:41
tags: ctf
---

## cat flag
明明显示当前用户对flag文件具有read权限，为啥就是不能够cat呢： 
![](https://i.loli.net/2018/12/14/5c1366142fcc7.png)  
用pwntools直接查看接收到的字节码：
![](https://i.loli.net/2018/12/14/5c13663d6afcd.png)
发现flag是被隐藏了，所谓的Permission Denied也不是系统返回的，而是flag文件的内容。  
从字节码序列可以看到，0x1b前面的字符被隐藏了，查询ASCII表0x1b对应的是ESC，但是具体原理是啥，没有找到比较好的解释

补充两个从其他人的writeup中找到的方法：
![](https://i.loli.net/2018/12/14/5c136d0c2a311.png)
![](https://i.loli.net/2018/12/14/5c136d1ef29be.png)
![](https://i.loli.net/2018/12/14/5c136d3640bb3.png)


## angrme
{% asset_link angrme 点击下载题目文件 %}  
其实这是一道非常基础的angr题目，但是因为我之前从来没有接触过angr，所以先用了一天的时间把angr的基础概念看了看，然后模仿其他ctf题目的脚本解出了这道题目：  
推荐教程：[CTF-All-In-One这本书5.3.1章节](https://github.com/firmianay/CTF-All-In-One)  
脚本如下：
```Python
#encoding=utf-8
import angr

find  = 0x00402370  # 输出:)的地址
avoid = 0x00402390  # 输出:(的地址

p = angr.Project('./angrme')
state = p.factory.entry_state()
pg = p.factory.simgr(state)
ex = pg.explore(find=find, avoid=avoid)

print pg.found[0].posix.dumps(0)
```
脚本运行的结果：
![](https://i.loli.net/2018/12/14/5c13754558e44.png)



