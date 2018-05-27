# 使用Jpcap发送ARP以及ICMP请求
## 一、实验过程
![这里写图片描述](https://img-blog.csdn.net/20180527190932901?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3djaHN0cmlmZQ==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)

 1. 首先获取本地的网卡以及IP信息 
 2. 输入当前网关的地址，在这个拓扑图中也就是**172.17.5.1** 
 3. 程序封装ARP请求，向网关发送ARP请求
 4. 抓取ARP相应的包，过滤之后获得网关的MAC地址
 5. 输入要PING的目的IP，即**172.16.5.7**
 6. 抓取ICMP相应的包，过滤之后输出ECHO和REPLY的包

**PS：特别注意**
**在ARP的发送的包中：**
源IP和源MAC地址是自己本地的IP（172.17.5.6）和MAC地址
目的IP是网关的IP（172.17.5.1），目的MAC地址是全F（表示广播，此时并不知道目的MAC地址）
**在ICMP的发送的包中：**
源IP和源MAC地址是自己本地的IP（172.17.5.6）和MAC地址
目的IP是PC2的IP（172.16.5.7），目的MAC地址是网关的MAC（也就是之前ARP获得的MAC地址）

> 之所以目的MAC地址是网关的MAC地址，而不是PC2的MAC地址。
> 是因为所有的数据包只需要交给路由器负责分组转发即可。
> 本身并不需要知道另一个网段的IP和MAC的映射关系。
> 但是，一些路由器会有ARP代理的功能，简单来说就是如果有这项功能的话，目的MAC地址写PC2的MAC地址也会成功的发送出去。

## 二、项目结构
![这里写图片描述](https://img-blog.csdn.net/20180527192659715?watermark/2/text/aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3djaHN0cmlmZQ==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70)

**Packet包**：下面所有的Packet来源于Jpcap的源码，是各个报文的字段的属性，在这个项目中并没有用到
**Util包：**下面是将byte[]转化为int方便输出的工具类
**ARP：**程序的入口，运行Main函数即可运行
**JpcapPacket：** demo程序，用于检测环境是否搭配好
**ARPAttackTest、ARPCheatAttack：**用于测试ARP攻击

## 三、运行
1. 搭建开发环境：[如何搭建开发环境](https://blog.csdn.net/wchstrife/article/details/79922073)
2. 运行ARP中的Main函数