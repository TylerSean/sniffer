# 实验一A 嗅探器设计与实现

## 实验要求

实现一款网络嗅探器（Network Packet Sniffer，NPS），它是一种专门用来进行网络流量侦听的工具。要求如下：

1、要求实现网络协议分析（Network Protocol Analyzer，NPA）的功能。

2、要有一定的协议过滤能力，Wireshark等软件的协议过滤器支持逻辑演算，所以该软件里含有逻辑推导的组件。基本的协议过滤需要支持筛选HTTP、TCP/UDP、IPv4/v6、ICMP等不同类型、层次的数据包。libpcap提供了数据包筛选功能。winPcap是基于Windows NT内核定制的libpcap。

3、要求有一定的流追踪能力：

- 基于 IP + Port 的 TCP 流
- 某进程产生的所有 TCP 流

4、要有图形化界面。

5、使用Linux BPF技术来实现。

## 需求分析

为实现一个网络嗅探器，我们需要采用以下技术：

1. Linux BPF技术：BPF是Berkeley Packet Filter的简称，是Linux内核中一个用于高效过滤数据包的技术。它允许我们在内核空间过滤数据包，并只将需要的数据包传递给用户空间进行进一步处理。这个技术非常高效，可以显著降低网络嗅探器的CPU使用率。
2. libpcap库：libpcap库是一个基于C语言的网络嗅探器库，它提供了一个高效的数据包捕获接口，可以让我们轻松地捕获网络数据包，并进行协议分析和流追踪等操作。
3. GTK+图形化界面：GTK+是一个用于开发图形化用户界面的跨平台工具包，它支持多种编程语言，如C、C++、Python等。我们可以使用GTK+来开发一个漂亮的图形化用户界面，让用户能够方便地操作网络嗅探器。

## 代码实现

在运行代码前，先安装常用的python包：

```bash
pip install PyQt5 scapy numpy matplotlib -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 入口函数

这段代码主要是一个 Python GUI 应用程序的入口函数，用于启动一个网络嗅探器的图形用户界面。代码如下：

```python
import imp
from SnifferGui import *
from SnifferController import *
from Sniffer import *
import sys
import os

if __name__ == "__main__":
    try:
        os.chdir(sys.path[0]) #设置相对路径
        app = QtWidgets.QApplication(sys.argv) #创建应用程序实例 app
        ui = SnifferGui() #创建 SnifferGui 实例 ui
        MainWindow = QtWidgets.QMainWindow() #创建主窗口实例 MainWindow
        ui.setupUi(MainWindow) #将 SnifferGui 实例 ui 设置为主窗口 MainWindow 的界面
        MainWindow.show() #显示主窗口
        sc = SnifferController(ui) #创建 SnifferController 实例 sc
        sc.loadAdapterIfaces() #加载网络适配器接口
        sc.setConnection() #设置网络连接
        sys.exit(app.exec_()) #运行程序，等待退出
    except ImportError as  e:
            QtWidgets.QMessageBox.critical(None,"错误",str(e))
    except Exception as e2:
            QtWidgets.QMessageBox.critical(None,"错误",str(e2))
    
```

### Sniffer模块

这段代码定义了一个名为Sniffer的类，这个类继承自QtCore.QThread类，因此它是一个线程类。主要功能是监听网络流量并将捕获的数据包发送到HandleSignal信号，HandleSignal信号可以被其他的Qt组件连接并接收到数据包。

这个类具有如下方法和属性：

**属性**：

- filter：网络过滤器，可以用来指定捕获哪些网络数据包。
- iface：网络接口名字，用于指定监听哪个网络接口的数据包。
- conditionFlag：线程挂起标志，当它被设置为True时，线程将暂停。
- mutex_1：互斥锁，用于线程同步。
- cond：条件变量，用于线程同步。

**方法**：

- run()：线程运行函数，不断监听网络流量并将捕获的数据包发送到HandleSignal信号中，该函数可以无限循环运行。
- pause()：暂停线程运行，将conditionFlag标志设置为True，线程会在下一个循环迭代中停止运行。
- resume()：恢复线程运行，将conditionFlag标志设置为False，同时唤醒线程并继续执行。

```python
from socket import timeout
from scapy.all import *
import os
import time
import multiprocessing
from scapy.layers import http
import numpy as np
import matplotlib.pyplot as plt
import binascii
from PyQt5 import QtCore,QtGui,QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

class Sniffer(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.packet.Packet)#scapy.layers.l2.Ether)
    def __init__(self) -> None:
        super().__init__()
        self.filter = None
        self.iface = None
        self.conditionFlag = False
        self.mutex_1 = QMutex()
        self.cond = QWaitCondition()

    def run(self):
        while True :
            self.mutex_1.lock()
            if self.conditionFlag :
                self.cond.wait(self.mutex_1)
            sniff(filter=self.filter,iface=self.iface,prn=lambda x:self.HandleSignal.emit(x),count = 1,timeout=2)
            self.mutex_1.unlock()
            
    def pause(self):
        self.conditionFlag = True

    def resume(self):
        self.conditionFlag = False
        self.cond.wakeAll()   
```

### SnniferController模块

这段代码包含了一个 SnifferController 类，它用于控制数据包的捕获、过滤、解析和显示等功能。具体来说，该类包含以下方法：

- `__init__(self,ui)`：类的构造函数，用于初始化 SnifferController 类的成员变量。
- `getAdapterIfaces(self)`：获取当前计算机上的网络接口列表。
- `loadAdapterIfaces(self)`：将获取到的网络接口列表加载到工具的 UI 上。
- `setConnection(self)`：为 UI 上的按钮和菜单项等控件设置事件处理函数。
- `Start(self)`：启动数据包的捕获。
- `setSniffer(self)`：设置数据包捕获的过滤条件和网络接口。
- `myCallBack(self,packet)`：数据包捕获回调函数，用于解析捕获到的数据包，并将解析结果添加到 UI 上的表格控件中。
- `PostFilter(self)`：应用 UI 上设置的过滤条件，过滤当前表格中的数据。
- `Stop(self)`：暂停数据包的捕获。
- `Filter(self)`：构建 UI 上的数据包过滤条件。
- `Trace(self)`：打开 UI 上的数据包跟踪窗口。
- `Save(self)`：将选中的数据包保存到指定的文件中。

```python
from PyQt5.QtWidgets import *
from Sniffer import *
from SnifferGui import *
import time
from parsePacket import *
class SnifferController():
    def __init__(self,ui):
        self.ui = ui
        self.sniffer = None

    def getAdapterIfaces(self):
        c = []
        for i in repr(conf.route).split('\n')[1:]:
            #tmp = i[50:94].rstrip()
            tmp = re.search(r'[a-zA-Z](.*)[a-zA-Z0-9]',i).group()[0:44].rstrip()
            if len(tmp)>0:
                c.append(tmp)
        c = list(set(c))
        return c

    def loadAdapterIfaces(self):
        ifaces  = self.getAdapterIfaces()
        self.ui.setAdapterIfaces(ifaces)
    
    def setConnection(self):
        self.ui.buttonStart.clicked.connect(self.Start)    
        self.ui.buttonPause.clicked.connect(self.Stop)
        self.ui.buttonFilter.clicked.connect(self.Filter)
        self.ui.tableWidget.itemClicked.connect(self.ui.showItemDetail)
        self.ui.buttonPostFilter.clicked.connect(self.PostFilter)
        self.ui.tableWidget.customContextMenuRequested.connect(self.ui.showContextMenu)
        self.ui.TraceAction.triggered.connect(self.Trace)
        self.ui.saveAction.triggered.connect(self.Save)
        self.ui.buttonRe.clicked.connect(self.ui.Reset)
       
    def Start(self):
        if self.sniffer is None:
            self.ui.startTime = time.time()
            self.sniffer = Sniffer()
            self.setSniffer()
            self.sniffer.HandleSignal.connect(self.myCallBack)
            self.sniffer.start()
            print('start sniffing')
        elif self.sniffer.conditionFlag :
            if self.ui.iface != self.ui.comboBoxIfaces.currentText()  or self.sniffer.filter != self.ui.filter :
                self.setSniffer()
                self.ui.clearTable()
            self.sniffer.resume()

    def setSniffer(self):
        self.sniffer.filter = self.ui.filter
        self.sniffer.iface=self.ui.comboBoxIfaces.currentText()
        self.ui.iface = self.ui.comboBoxIfaces.currentText()
    
    def myCallBack(self,packet):
        if self.ui.filter ==  'http' or self.ui.filter ==  'https':
            if packet.haslayer('TCP') ==False:
                return
            if packet[TCP].dport != 80 and packet[TCP].sport != 80 and packet[TCP].dport != 443 and packet[TCP].sport != 443:
                return                
        res = []
        myPacket = MyPacket()
        myPacket.parse(packet,self.ui.startTime)
        packetTime = myPacket.packTimne
        lens = myPacket.lens
        src = myPacket.layer_3['src']
        dst = myPacket.layer_3['dst']
        type = None
        info = None
        if myPacket.layer_1['name'] is not None:
            type = myPacket.layer_1['name']
            info = myPacket.layer_1['info']
        elif myPacket.layer_2['name'] is not None:
            type = myPacket.layer_2['name']
            info = myPacket.layer_2['info']
        elif myPacket.layer_3['name'] is not None:
            type = myPacket.layer_3['name']
            info = myPacket.layer_3['info']

        res.append(packetTime)
        res.append(src)
        res.append(dst)
        res.append(type)
        res.append(lens)
        res.append(info)
        res.append(myPacket)
        self.ui.setTableItems(res)

    def PostFilter(self):
        self.ui.postFilter()
    
    def Stop(self):
        self.sniffer.pause()

    def Filter(self):
        self.ui.buildFilter()
    def Trace(self):
        self.ui.Trace()
    
    def Save(self):
        try:
            row = self.ui.tableWidget.currentRow()     #获取当前行数
            packet = self.ui.packList[row].packet
            path, filetype = QtWidgets.QFileDialog.getSaveFileName(None,
                                    "选择保存路径",
                                    "./",
                                    "pcap文件(*.cap);;全部(*)")
            if path == "":
                return
            if os.path.exists(os.path.dirname(path)) == False:
                QtWidgets.QMessageBox.critical(None,"错误","路径不存在")
                return
        
            wrpcap(path,packet)
            QtWidgets.QMessageBox.information(None,"成功","保存成功")
        except ImportError as  e:
            QtWidgets.QMessageBox.critical(None,"错误",str(e))
```

### parsePacket模块

这段代码实现了对网络数据包的解析，分析其各层的信息并提取关键信息。

代码使用了Python的`unicodedata`和`scapy`库，并定义了一个`MyPacket`类。`unicodedata`库是Python标准库，提供了Unicode字符数据库的访问功能。`scapy`库是一个强大的网络数据包处理工具，可以用于创建、发送、捕获和分析网络数据包。`MyPacket`类包含了对数据包各层信息的解析和提取。

具体来说，`MyPacket`类的`__init__`方法定义了数据包的各层信息，包括第四层（TCP、UDP、ICMP、IGMP、其他协议）、第三层（IP、ARP）和第二层（Ethernet、Loopback）。每个层次的信息都用字典表示，并包含了该层次的各种字段，如源地址、目的地址、协议类型等。

`MyPacket`类的`parse`方法实现了对数据包的解析，其中startTime为程序启动时间，用于计算数据包到达时间。`parseLayer_4`方法解析第四层信息，根据数据包类型（IPv4、IPv6、ARP等）选择相应的解析方式。`parseLayer_3`方法解析第三层信息，同样根据数据包类型选择相应的解析方式。`parseLayer_2`方法解析第二层信息，根据数据包类型和IP版本选择相应的解析方式。最后，提取出各层信息的关键字段，存入各自的字典中。

这段代码是一个解析网络数据包的类`MyPacket`，其中的方法实现了对网络数据包的解析和存储。具体来说，它提供了以下四个层次的解析和存储：

- 第一层是链路层，解析和存储MAC地址等信息；
- 第二层是网络层，解析和存储IP地址等信息；
- 第三层是传输层，解析和存储TCP/UDP等协议的信息；
- 第四层是应用层，解析和存储HTTP/HTTPS等协议的信息。

具体来说，该类的各个方法的作用如下：

- `__init__(self)`：初始化该类的各个成员变量，分别存储各个层次的信息。
- `parse(self, packet, startTime)`：解析数据包的各个层次信息，并存储在该类的成员变量中。其中，`packet`是一个`scapy`库中的数据包对象，`startTime`是数据包抓取的起始时间。
- `parseLayer_4(self, packet)`：解析数据包的传输层信息（TCP/UDP等），并存储在该类的成员变量中。
- `parseLayer_3(self, packet)`：解析数据包的网络层信息（IP地址等），并存储在该类的成员变量中。其中，该方法会调用`parseLayer_2()`方法来解析传输层信息。
- `parseLayer_2(self, packet, layer)`：解析数据包的传输层信息（TCP/UDP等），并存储在该类的成员变量中。其中，`layer`表示传输层协议的类型（4表示TCP，6表示UDP）。
- 其他一些成员变量和方法的作用是存储和解析各种协议的信息，如链路层协议、ARP协议等。

该类的具体实现使用了Python中的`scapy`库来解析数据包的各个层次信息。同时，为了方便解析和存储各种协议的信息，该类使用了Python中的字典数据结构来存储这些信息。

```python
from unicodedata import name
from scapy.all import *
import time

class MyPacket():
    def __init__(self) -> None:
        # ether  loopback
        self.packTimne = None
        self.lens = None
        self.packet = None
        self.tcptrace = None
        self.layer_4 = {'name' : None, 'src': None, 'dst': None,'info':None}
        # IP ARP
        self.layer_3 = {'name' : None, 'src': None, 'dst': None,'version': None,\
            'ihl': None, 'tos': None, 'len': None, 'id': None, 'flag': None, 'chksum':None,\
            'opt':None, 'hwtype':None, 'ptype':None, 'hwlen':None,'type':None,'op':None,\
            'info':None, 'hwsrc':None, 'hwdst':None
            }
        #TCP UDP ICMP IGMP OTHERS
        self.layer_2 = {'name':None, 'src': None, 'dst': None, 'seq':None, 'ack':None,\
            'dataofs':None, 'reserved':None, 'flag':None, 'len':None, 'chksum':None,\
            'type':None, 'code':None, 'id':None,'info':None, 'window':None, 'tcptrace':None,\
            'tcpSdTrace': None, 'tcpRcTrace':None
            }
        #HTTP HTTPS
        self.layer_1 = {'name':None, 'info':None}
    
    def parse(self,packet,startTime):
        self.packTimne = '{:.7f}'.format(time.time() - startTime)
        self.lens = str(len(packet))
        self.packet = packet
        self.parseLayer_4(packet)
    
    def parseLayer_4(self,packet):
        if packet.type == 0x800 or packet.type == 0x86dd or packet.type == 0x806:
            self.layer_4['name'] = 'Ethernet'
            self.layer_4['src'] = packet.src
            self.layer_4['dst'] = packet.dst
            self.layer_4['info'] = ('Ethernet，源MAC地址(src)：'+ packet.src + '，目的MAC地址(dst)：'+packet.dst)
        elif packet.type == 0x2 or packet.type == 0x18:
            self.layer_4['name'] = 'Loopback'
            self.layer_4['info'] = 'Loopback'
        self.parseLayer_3(packet)
        
    def parseLayer_3(self,packet):
        if packet.type == 0x800 or packet.type == 0x2:#IPv4
            self.layer_3['name'] = 'IPv4'
            self.layer_3['src'] = packet[IP].src
            self.layer_3['dst'] = packet[IP].dst
            self.layer_3['version'] = packet[IP].version
            self.layer_3['ihl'] = packet[IP].ihl
            self.layer_3['tos'] = packet[IP].tos
            self.layer_3['len'] = packet[IP].len
            self.layer_3['id'] = packet[IP].id
            self.layer_3['flag'] = packet[IP].flags
            self.layer_3['chksum'] = packet[IP].chksum
            self.layer_3['opt'] = packet[IP].options
            self.layer_3['info'] = ('IPv4，源地址(src)：'+packet[IP].src+'，目的地址(dst)：'+packet[IP].dst)
            self.parseLayer_2(packet, 4)
        elif packet.type == 0x86dd or packet.type == 0x18:#IPv6
            self.layer_3['name'] = 'IPv6'
            self.layer_3['src'] = packet[IPv6].src
            self.layer_3['dst'] = packet[IPv6].dst
            self.layer_3['version'] = packet[IPv6].version
            self.layer_3['info'] = ('IPv6，源地址(src)：'+packet[IPv6].src+'，目的地址(dst)：'+packet[IPv6].dst)
            self.parseLayer_2(packet, 6)
        elif packet.type == 0x806 : #ARP
            self.layer_3['name'] = 'ARP'
            self.layer_3['src'] = packet[ARP].psrc
            self.layer_3['dst'] = packet[ARP].pdst
            self.layer_3['op'] = packet[ARP].op 
            self.layer_3['hwtype'] = packet[ARP].hwtype
            self.layer_3['ptype'] = packet[ARP].ptype
            self.layer_3['hwlen'] = packet[ARP].hwlen
            self.layer_3['len'] = packet[ARP].plen
            self.layer_3['hwsrc'] = packet[ARP].hwsrc
            self.layer_3['hwdst'] = packet[ARP].hwdst
            if packet[ARP].op == 1:  #request
                self.layer_3['info'] = ('Request: Who has %s? Tell %s' % (packet[ARP].pdst,packet[ARP].psrc))
            elif packet[ARP].op == 2:  #reply
                self.layer_3['info'] = ('Reply: %s is at %s' % (packet[ARP].psrc,packet[ARP].hwsrc))
            else:
                self.layer_3['info'] = ('操作: '+ packet[ARP].op )

    def parseLayer_2(self,packet,num):
        if num == 4:
            if packet[IP].proto == 6:#TCP
                self.layer_2['tcptrace'] = ('%s %s %s %s' % (packet[IP].src, packet[IP].dst,packet[TCP].sport, packet[TCP].dport))
                self.layer_2['tcpSdTrace'] = ('%s %s' % (packet[IP].src,packet[TCP].sport))
                self.layer_2['tcpRcTrace'] = ('%s %s' % (packet[IP].dst, packet[TCP].dport))
                self.layer_2['name'] = 'TCP'
                self.layer_2['src'] = packet[TCP].sport
                self.layer_2['dst'] = packet[TCP].dport
                self.layer_2['seq'] = packet[TCP].seq
                self.layer_2['ack'] = packet[TCP].ack
                self.layer_2['window'] = packet[TCP].window
                self.layer_2['dataofs'] = packet[TCP].dataofs
                self.layer_2['reserved'] = packet[TCP].reserved
                self.layer_2['flag'] = packet[TCP].flags
                self.layer_2['info'] = ('源端口%s -> 目的端口%s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.parseLayer_1(packet, 4)
                elif  packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    self.parseLayer_1(packet, 6)
            elif packet[IP].proto == 17:#UDP
                self.layer_2['name'] = 'UDP'
                self.layer_2['src'] = packet[UDP].sport
                self.layer_2['dst'] = packet[UDP].dport
                self.layer_2['len'] = packet[UDP].len
                self.layer_2['chksum'] = packet[UDP].chksum
                self.layer_2['info'] =  ('源端口%s -> 目的端口%s 长度(len)：%s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))
                if packet.haslayer('DNS'):
                    self.parseLayer_1(packet, 7)
            elif packet[IP].proto == 1:#ICMP
                self.layer_2['name'] = 'ICMP'
                self.layer_2['type'] = packet[ICMP].type
                self.layer_2['code'] = packet[ICMP].code
                self.layer_2['id'] = packet[ICMP].id
                self.layer_2['chksum'] = packet[ICMP].chksum
                self.layer_2['seq'] = packet[ICMP].seq
                if packet[ICMP].type == 8:
                    self.layer_2['info'] = ('Echo (ping) request id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq))
                elif packet[ICMP].type == 0:
                    self.layer_2['info'] = ('Echo (ping) reply id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq))
                else:
                    self.layer_2['info'] = ('type：%s id：%s seq：%s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq))      
            elif packet[IP].proto == 2:#IGMP
                self.layer_2['name'] = 'IGMP'
                self.layer_2['len'] = packet[IPOption_Router_Alert].length
                self.layer_2['info'] = 'IGMP协议，等待补充'
            else:
                self.layer_2['name'] = str(packet[IP].proto)
                self.layer_2['info'] = '未知协议，等待补充'
        elif num == 6:
            if packet[IPv6].nh == 6:#TCP
                self.layer_2['tcptrace'] = ('%s %s %s %s' % (packet[IPv6].src, packet[IPv6].dst,packet[TCP].sport, packet[TCP].dport))
                self.layer_2['tcpSdTrace'] = ('%s %s' % (packet[IPv6].src,packet[TCP].sport))
                self.layer_2['tcpRcTrace'] = ('%s %s' % (packet[IPv6].dst, packet[TCP].dport))
                self.layer_2['name'] = 'TCP'
                self.layer_2['src'] = packet[TCP].sport
                self.layer_2['dst'] = packet[TCP].dport
                self.layer_2['seq'] = packet[TCP].seq
                self.layer_2['ack'] = packet[TCP].ack
                self.layer_2['window'] = packet[TCP].window
                self.layer_2['dataofs'] = packet[TCP].dataofs
                self.layer_2['reserved'] = packet[TCP].reserved
                self.layer_2['flag'] = packet[TCP].flags
                self.layer_2['info'] = ('源端口%s ->目的端口 %s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.parseLayer_1(packet, 4)
                elif  packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    self.parseLayer_1(packet, 6)
            elif packet[IPv6].nh == 17:#UDP
                self.layer_2['name'] = 'UDP'
                self.layer_2['src'] = packet[UDP].sport
                self.layer_2['dst'] = packet[UDP].dport
                self.layer_2['len'] = packet[UDP].len
                self.layer_2['chksum'] = packet[UDP].chksum
                self.layer_2['info'] =  ('源端口：%s -> 目的端口%s 长度(len)：%s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))
                if packet.haslayer('DNS'):
                    self.parseLayer_1(packet, 7)
            elif packet[IPv6].nh == 1:#ICMP
                self.layer_2['name'] = 'ICMP'
                self.layer_2['type'] = packet[ICMP].type
                self.layer_2['code'] = packet[ICMP].code
                self.layer_2['id'] = packet[ICMP].id
                self.layer_2['chksum'] = packet[ICMP].chksum
                self.layer_2['seq'] = packet[ICMP].seq
                if packet[ICMP].type == 8:
                    self.layer_2['info'] = ('Echo (ping) request id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq))
                elif packet[ICMP].type == 0:
                    self.layer_2['info'] = ('Echo (ping) reply id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq))
                else:
                    self.layer_2['info'] = ('type：%s id：%s seq：%s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq))    
            elif packet[IPv6].nh == 2:#IGMP
                self.layer_2['name'] = 'IGMP'
                self.layer_2['len'] = packet[IPOption_Router_Alert].length
                self.layer_2['info'] = 'IGMP协议，等待补充'
            else:
                self.layer_2['name'] = str(packet[IPv6].nh)
                self.layer_2['info'] = '未知协议，等待补充'

    def parseLayer_1(self,packet,num):
        if num == 4:#HTTP
            self.layer_1['name'] ='HTTP'
            if packet.haslayer('HTTPRequest'):
                self.layer_1['info'] = ('%s %s %s' % (packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}").strip("'"),packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}").strip("'"),packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}").strip("'")))
            elif packet.haslayer('HTTPResponse'):
                self.layer_1['info'] = ('%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}").strip("'"))
             
        elif num ==6:#HTTPS
            self.layer_1['name'] ='HTTPS'
            self.layer_1['info'] = ('%s -> %s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
        elif num == 7:#DNS
            self.layer_1['name'] ='DNS'
            if packet[DNS].opcode == 0:#Query
                tmp = '??'
                if packet[DNS].qd :
                    tmp = bytes.decode(packet[DNS].qd.qname)
                self.layer_1['info'] = ('源端口：%s -> 目的端口%s 长度(len)：%s DNS 查询: %s 在哪里' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len,tmp))
            else:
                self.layer_1['info'] = ('源端口：%s -> 目的端口%s 长度(len)：%s DNS 回答' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))
```

### SnniferGui模块

这段代码是一个基于PyQt5和Scapy库实现的网络数据包嗅探器的GUI界面部分。主要功能包括：

1. 显示网络数据包的基本信息，如序号、时间、源地址、目的地址、协议、长度和信息等；
2. 显示网络数据包的分层信息，包括链路层、网络层和传输层；
3. 右键菜单，提供了一些操作选项；
4. 工具栏，包括开始嗅探和停止嗅探等操作。

具体实现方式：

1. 导入所需模块和库文件；
2. 创建一个名为SnifferGui的类，并初始化一些成员变量；
3. 创建GUI界面，包括顶部栏、状态栏、菜单栏和主显示区域；
4. 设置右键菜单和工具栏，包括开始嗅探和停止嗅探等操作；
5. 实现显示网络数据包的基本信息和分层信息的函数；
6. 实现处理右键菜单选项的函数；
7. 实现启动和停止嗅探的函数。

下面是各个函数的作用：

- `setupUi(self, MainWindow)`：设置 GUI 界面的布局和组件，包括主窗口、状态栏、菜单栏等等。
- `retranslateUi(self, MainWindow)`：设置各个组件的显示文本，如表格的表头和工具栏的标题等。
- `showContextMenu(self)`：右键点击时调用的函数，用于显示上下文菜单。
- `setAdapterIfaces(self,c)`：将网卡接口信息显示到下拉列表框中。
- `setTableItems(self,res)`：将捕获到的数据包的信息显示到表格中。
- `setLayer_5(self,row,times)`：将数据包的第 5 层协议信息显示在树形控件中。
- `setLayer_4(self,packet)`：将数据包的第 4 层协议信息显示在树形控件中。
- `setLayer_3(self,packet)`：将数据包的第 3 层协议信息显示在树形控件中。

其中 `setupUi(self, MainWindow)` 函数是最为关键的，它定义了 GUI 界面的整体布局，包括一个主窗口，一个状态栏，一个菜单栏，一个表格和一个树形控件等等。各个函数的作用则是在这个布局中，将捕获到的数据包的信息显示到对应的组件中，以便用户对网络流量进行分析。

```python
from ast import dump
from PyQt5 import QtCore,QtGui,QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import sys
import os
from scapy.all import *
import time

class SnifferGui(object):
    def setupUi(self, MainWindow):
        self.MainWindow = MainWindow
        self.startTime = None
        self.filter = None
        self.iface = None
        self.packList = []
        global counts
        global displays
        counts = 0
        displays = 0
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1244, 890)
        MainWindow.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        #central widget
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        #顶部栏 状态栏 菜单栏
        self.gridLayoutBar = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayoutBar.setObjectName("gridLayoutBar")
        #主显示
        self.gridLayoutMainShow = QtWidgets.QGridLayout()
        self.gridLayoutMainShow.setObjectName("gridLayoutMainShow")
        #下面部份
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        
        self.textBrowserTmp = QtWidgets.QTextBrowser(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(self.textBrowserTmp.sizePolicy().hasHeightForWidth())
        self.textBrowserTmp.setSizePolicy(sizePolicy)
        self.textBrowserTmp.setObjectName("textBrowserTmp")
        self.horizontalLayout.addWidget(self.textBrowserTmp)

        self.textBrowserShow = QtWidgets.QTextBrowser(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(3)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(self.textBrowserShow.sizePolicy().hasHeightForWidth())
        self.textBrowserShow.setSizePolicy(sizePolicy)
        self.textBrowserShow.setObjectName("textBrowserShow")
        self.horizontalLayout.addWidget(self.textBrowserShow)

        self.gridLayoutMainShow.addLayout(self.horizontalLayout, 2, 0, 1, 1)#rowIndex,colIndex,rowWidth,colWidth

        #中间部分
        self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(3)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(self.treeWidget.sizePolicy().hasHeightForWidth())
        self.treeWidget.setSizePolicy(sizePolicy)
        self.treeWidget.setObjectName("treeWidget")
        self.treeWidget.headerItem().setText(0, "root")
        self.gridLayoutMainShow.addWidget(self.treeWidget, 1, 0, 1, 1)

        #上面部分
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(3)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(7)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(6, item)
        self.gridLayoutMainShow.addWidget(self.tableWidget, 0, 0, 1, 1)
        self.tableWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.contextMenu = QMenu(self.tableWidget)
        self.saveAction = self.contextMenu.addAction(u'另存为cap')
        self.TraceAction = self.contextMenu.addAction(u'追踪TCP')

        #顶部工具栏 菜单栏 状态栏
        self.gridLayoutBar.addLayout(self.gridLayoutMainShow, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.toolbar = QtWidgets.QToolBar(MainWindow)
        self.toolbar.setObjectName("toolbar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolbar)
        self.toolbar.addSeparator()

        self.comboBoxIfaces = QComboBox()
        self.toolbar.addWidget(self.comboBoxIfaces)
        self.toolbar.addSeparator()

        QToolTip.setFont(QFont('SansSerif', 30))
        self.buttonStart = QtWidgets.QPushButton()
        self.buttonStart.setIcon(QIcon("./static/start.png"))
        self.buttonStart.setStyleSheet("background:rgba(0,0,0,0);border:1px solid rgba(0,0,0,0);border-radius:5px;")
        self.buttonStart.setToolTip("开始捕获")
        self.toolbar.addWidget(self.buttonStart)
        self.toolbar.addSeparator()

        self.buttonPause = QtWidgets.QPushButton()
        self.buttonPause.setIcon(QIcon("./static/pause.png"))
        self.buttonPause.setStyleSheet("background:rgba(0,0,0,0);border:1px solid rgba(0,0,0,0);border-radius:5px;")
        self.buttonPause.setToolTip("暂停捕获")
        self.toolbar.addWidget(self.buttonPause)
        self.toolbar.addSeparator()

        self.buttonFilter = QtWidgets.QPushButton()
        self.buttonFilter.setIcon(QIcon("./static/filter.png"))
        self.buttonFilter.setStyleSheet("background:rgba(0,0,0,0);border:1px solid rgba(0,0,0,0);border-radius:5px;")
        self.buttonFilter.setToolTip("先停止捕获，捕获前过滤筛选")
        self.toolbar.addWidget(self.buttonFilter)
        self.toolbar.addSeparator()

        self.buttonPostFilter = QtWidgets.QPushButton()
        self.buttonPostFilter.setIcon(QIcon("./static/search.png"))
        self.buttonPostFilter.setStyleSheet("background:rgba(0,0,0,0);border:1px solid rgba(0,0,0,0);border-radius:5px;")
        self.buttonPostFilter.setToolTip("先停止捕获，捕获后过滤筛选")
        self.toolbar.addWidget(self.buttonPostFilter)
        self.toolbar.addSeparator()

        self.buttonRe = QtWidgets.QPushButton()
        self.buttonRe.setIcon(QIcon("./static/reset.png"))
        self.buttonRe.setStyleSheet("background:rgba(0,0,0,0);border:1px solid rgba(0,0,0,0);border-radius:5px;")
        self.buttonRe.setToolTip("清空捕获后筛选记录,显示所有结果")
        self.toolbar.addWidget(self.buttonRe)
        self.toolbar.addSeparator()
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "SnifferGui"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "序号"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "时间"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "源地址"))
        item = self.tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "目的地址"))
        item = self.tableWidget.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "协议"))
        item = self.tableWidget.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "长度"))
        item = self.tableWidget.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "信息"))
        self.toolbar.setWindowTitle(_translate("MainWindow", "工具栏"))
        #self.buttonStart.setText(_translate("MainWindow", "开始"))

        self.tableWidget.horizontalHeader().setSectionsClickable(False) #可以禁止点击表头的列
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows) #设置 不可选择单个单元格，只可选择一行。
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers) #设置表格不可更改
        self.tableWidget.verticalHeader().setVisible(False) #去掉垂直表头
        self.tableWidget.setColumnWidth(0,60)
        self.tableWidget.setColumnWidth(2,150)
        self.tableWidget.setColumnWidth(3,150)
        self.tableWidget.setColumnWidth(4,60)
        self.tableWidget.setColumnWidth(5,60)
        self.tableWidget.setColumnWidth(6,600)

        self.treeWidget.setHeaderHidden(True) #去掉表头
        self.treeWidget.setColumnCount(1)

        self.timer = QTimer(self.MainWindow)
        self.timer.timeout.connect(self.statistics)
        #开启统计
        self.timer.start(1000)

    def showContextMenu(self):
        '''
        右键点击时调用的函数
        '''
        self.contextMenu.exec_(QCursor.pos())

    def setAdapterIfaces(self,c):
        self.comboBoxIfaces.addItems(c)

    def setTableItems(self,res):
        global counts
        global displays
        counts += 1
        displays = counts
        if res :
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row,0, QtWidgets.QTableWidgetItem(str(counts)))
            self.tableWidget.setItem(row,1,QtWidgets.QTableWidgetItem(res[0]))
            self.tableWidget.setItem(row,2, QtWidgets.QTableWidgetItem(res[1]))
            self.tableWidget.setItem(row,3, QtWidgets.QTableWidgetItem(res[2]))
            self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem(res[3]))
            self.tableWidget.setItem(row,5, QtWidgets.QTableWidgetItem(res[4]))
            self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem(res[5]))
            self.packList.append(res[6])
    
    def setLayer_5(self,row,times):
        num = self.tableWidget.item(row,0).text()
        Time = self.tableWidget.item(row,1).text()
        length = self.tableWidget.item(row,5).text()
        iface = self.iface
        timeformat = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(times))
        Frame = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Frame.setText(0,'Frame %s：%s bytes on %s' % (num,length,iface))
        FrameIface = QtWidgets.QTreeWidgetItem(Frame)
        FrameIface.setText(0,'网卡设备：%s' % iface)
        FrameArrivalTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameArrivalTime.setText(0,'到达时间：%s' % timeformat)
        FrameTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameTime.setText(0,'距离第一帧时间：%s' % Time)
        FrameNumber = QtWidgets.QTreeWidgetItem(Frame)
        FrameNumber.setText(0,'序号：%s' % num)
        FrameLength = QtWidgets.QTreeWidgetItem(Frame)
        FrameLength.setText(0,'帧长度：%s' % length)

    def setLayer_4(self,packet):
        if packet.layer_4['name']  == 'Ethernet':
            Ethernet_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            Ethernet_.setText(0,packet.layer_4['info'])
            EthernetDst = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetDst.setText(0,'目的MAC地址(dst)：'+ packet.layer_4['dst'])
            EthernetSrc = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetSrc.setText(0,'源MAC地址(src)：'+ packet.layer_4['src'])
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetType.setText(0,'协议类型(type)：'+ packet.layer_3['name'])
        elif packet.layer_4['name']  == 'Loopback':
            Loopback_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            Loopback_.setText(0,packet.layer_4['info'])
            LoopbackType = QtWidgets.QTreeWidgetItem(Loopback_)
            LoopbackType.setText(0,'协议类型(type)：'+ packet.layer_3['name'])
        
    def setLayer_3(self,packet):
        if packet.layer_3['name'] == 'IPv4':
            IPv4 = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv4.setText(0,packet.layer_3['info'])
            IPv4Version = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Version.setText(0,'版本(version)：%s'% packet.layer_3['version'])
            IPv4Ihl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ihl.setText(0,'包头长度(ihl)：%s' % packet.layer_3['ihl'])
            IPv4Tos = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Tos.setText(0,'服务类型(tos)：%s'% packet.layer_3['tos'])
            IPv4Len = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Len.setText(0,'总长度(len)：%s' % packet.layer_3['len']) #IP报文的总长度。报头的长度和数据部分的长度之和。
            IPv4Id = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Id.setText(0,'标识(id)：%s' % packet.layer_3['id'])  #唯一的标识主机发送的每一分数据报。通常每发送一个报文，它的值加一。当IP报文长度超过传输网络的MTU（最大传输单元）时必须分片，这个标识字段的值被复制到所有数据分片的标识字段中，使得这些分片在达到最终目的地时可以依照标识字段的内容重新组成原先的数据。
            IPv4Flags = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Flags.setText(0,'标志(flags)：%s' % packet.layer_3['flag']) #R、DF、MF三位。目前只有后两位有效，DF位：为1表示不分片，为0表示分片。MF：为1表示“更多的片”，为0表示这是最后一片。
            IPv4Chksum = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Chksum.setText(0,'校验和(chksum)：0x%x' % packet.layer_3['chksum'])
            IPv4Src = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Src.setText(0,'源IP地址(src)：%s' % packet.layer_3['src'])
            IPv4Dst = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Dst.setText(0,'目的IP地址(dst)：%s' % packet.layer_3['dst'])
            IPv4Options = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Options.setText(0,'可选部分(options)：%s' % packet.layer_3['opt'])
            IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Proto.setText(0,'协议类型(proto)：%s' % packet.layer_2['name'])
        elif packet.layer_3['name'] == 'IPv6':
            IPv6_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv6_.setText(0, packet.layer_3['info'])
            IPv6Version = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Version.setText(0,'版本(version)：%s'% packet.layer_3['version'])
            IPv6Src = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Src.setText(0,'源IP地址(src)：%s' % packet.layer_3['src'])
            IPv6Dst = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Dst.setText(0,'目的IP地址(dst)：%s' % packet.layer_3['dst'])
            IPv6Proto = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Proto.setText(0,'协议类型(proto)：'+ packet.layer_2['name'])
        elif packet.layer_3['name'] == 'ARP':
            arp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            arp.setText(0, packet.layer_3['name'] + " "+ packet.layer_3['info'])
            arpHwtype = QtWidgets.QTreeWidgetItem(arp)
            arpHwtype.setText(0,'硬件类型(hwtype)：0x%x' % packet.layer_3['hwtype']) #1代表是以太网。
            arpPtype = QtWidgets.QTreeWidgetItem(arp)
            arpPtype.setText(0,'协议类型(ptype)：0x%x' % packet.layer_3['ptype']) #表明上层协议的类型,这里是0x0800,表示上层协议是IP协议
            arpHwlen = QtWidgets.QTreeWidgetItem(arp)
            arpHwlen.setText(0,'硬件地址长度(hwlen)：%s' % packet.layer_3['hwlen'])
            arpPlen = QtWidgets.QTreeWidgetItem(arp)
            arpPlen.setText(0,'协议长度(plen)：%s' % packet.layer_3['len'])
            arpOp = QtWidgets.QTreeWidgetItem(arp)
            arpOp.setText(0,'操作类型(op)： %s' % packet.layer_3['info'])
            arpHwsrc = QtWidgets.QTreeWidgetItem(arp)
            arpHwsrc.setText(0,'源MAC地址(hwsrc)：%s' % packet.layer_3['hwsrc'])
            arpPsrc = QtWidgets.QTreeWidgetItem(arp)
            arpPsrc.setText(0,'源IP地址(psrc)：%s' % packet.layer_3['src'])
            arpHwdst = QtWidgets.QTreeWidgetItem(arp)
            arpHwdst.setText(0,'目的MAC地址(hwdst)：%s' % packet.layer_3['hwdst'])
            arpPdst = QtWidgets.QTreeWidgetItem(arp)
            arpPdst.setText(0,'目的IP地址(pdst)：%s' % packet.layer_3['dst'])

    def setLayer_2(self,packet):
        if packet.layer_2['name'] == 'TCP':
            tcp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            tcp.setText(0, packet.layer_2['info'])
            tcpSport = QtWidgets.QTreeWidgetItem(tcp)
            tcpSport.setText(0,'源端口(sport)：%s' % packet.layer_2['src'])
            tcpDport = QtWidgets.QTreeWidgetItem(tcp)
            tcpDport.setText(0,'目的端口(sport)：%s' % packet.layer_2['dst'])
            tcpSeq = QtWidgets.QTreeWidgetItem(tcp)
            tcpSeq.setText(0,'序号(Seq)：%s' % packet.layer_2['seq'])
            tcpAck = QtWidgets.QTreeWidgetItem(tcp)
            tcpAck.setText(0,'确认号(Ack)：%s' % packet.layer_2['ack'])
            tcpDataofs = QtWidgets.QTreeWidgetItem(tcp)
            tcpDataofs.setText(0,'数据偏移(dataofs)：%s' % packet.layer_2['dataofs'])
            tcpReserved = QtWidgets.QTreeWidgetItem(tcp)
            tcpReserved.setText(0,'保留(reserved)：%s' % packet.layer_2['reserved'])
            tcpFlags = QtWidgets.QTreeWidgetItem(tcp)
            tcpFlags.setText(0,'标志(flags)：%s' % packet.layer_2['flag'])
        elif packet.layer_2['name'] == 'UDP':
            udp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            udp.setText(0,packet.layer_2['info'])
            udpSport = QtWidgets.QTreeWidgetItem(udp)
            udpSport.setText(0,'源端口(sport)：%s' % packet.layer_2['src'])
            udpDport = QtWidgets.QTreeWidgetItem(udp)
            udpDport.setText(0,'目的端口(dport)：%s' % packet.layer_2['dst'])
            udpLen = QtWidgets.QTreeWidgetItem(udp)
            udpLen.setText(0,'长度(len)：%s' % packet.layer_2['len'])
            udpChksum = QtWidgets.QTreeWidgetItem(udp)
            udpChksum.setText(0,'校验和(chksum)：0x%x' % packet.layer_2['chksum'])
        elif packet.layer_2['name'] == 'ICMP':
            icmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            icmp.setText(0,'ICMP')
            icmpType = QtWidgets.QTreeWidgetItem(icmp)
            icmpType.setText(0,'类型(type)：%s' % packet.layer_2['info'])  #占一字节，标识ICMP报文的类型，目前已定义了14种，从类型值来看ICMP报文可以分为两大类。第一类是取值为1~127的差错报文，第2类是取值128以上的信息报文。
            icmpCode = QtWidgets.QTreeWidgetItem(icmp)
            icmpCode.setText(0,'代码(code)：%s' % packet.layer_2['code'])  #占一字节，标识对应ICMP报文的代码。它与类型字段一起共同标识了ICMP报文的详细类型。
            icmpChksum = QtWidgets.QTreeWidgetItem(icmp)
            icmpChksum.setText(0,'校验和(chksum)：0x%x' % packet.layer_2['chksum'])
            icmpId = QtWidgets.QTreeWidgetItem(icmp)
            icmpId.setText(0,'标识(id)：%s' % packet.layer_2['id'])
        elif packet.layer_2['name'] == 'IGMP':
            igmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            igmp.setText(0,packet.layer_2['info'])
            igmpLength = QtWidgets.QTreeWidgetItem(igmp)
            igmpLength.setText(0,'length：%s' % packet.layer_2['len'])
        else:
            waitproto =  QtWidgets.QTreeWidgetItem(self.treeWidget)
            waitproto.setText(0,'协议号： %s' % packet.layer_2['name'])
            waitprotoInfo = QtWidgets.QTreeWidgetItem(waitproto)
            waitprotoInfo.setText(0,packet.layer_2['info'])

    def setLayer_1(self,packet):
        waitproto =  QtWidgets.QTreeWidgetItem(self.treeWidget)
        waitproto.setText(0, packet.layer_1['name'])
        waitprotoInfo = QtWidgets.QTreeWidgetItem(waitproto)
        waitprotoInfo.setText(0,packet.layer_1['info'])

    def showItemDetail(self):
        row = self.tableWidget.currentRow()     #获取当前行数
        mypacket = self.packList[row]

        self.treeWidget.clear()
        self.treeWidget.setColumnCount(1)
        self.setLayer_5(row,mypacket.packet.time) 
        self.setLayer_4(mypacket)
        self.setLayer_3(mypacket)
        if mypacket.layer_2['name'] is not None:
            self.setLayer_2(mypacket)
        if mypacket.layer_1['name'] is not None:
            self.setLayer_1(mypacket)
      
        self.textBrowserTmp.clear()
        content = mypacket.packet.show(dump=True)
        self.textBrowserTmp.append(content)

        self.textBrowserShow.clear()
        content = hexdump(mypacket.packet,dump=True)
        self.textBrowserShow.append(content)
        
    def statistics(self):
        global counts
        global displays
        if counts != 0:
            percent = '{:.1f}'.format(displays/counts*100)
            self.statusbar.showMessage('捕获：%s   已显示：%s (%s%%)' % (counts,displays,percent))

    def clearTable(self):
        global counts
        global displays
        counts = 0
        displays = 0
        self.tableWidget.setRowCount(0)
        self.treeWidget.clear()
        self.textBrowserTmp.clear()
        self.textBrowserShow.clear()
        self.packList = []

    def buildFilter(self):
        list = ["指定源IP地址","指定目的IP地址", "指定源端口","指定目的端口","指定协议类型"]   
        item, ok = QInputDialog.getItem(self.MainWindow, "捕获前选项","规则列表", list, 1, False)
        if ok:
            if item=="指定源IP地址":
                filter,ok_1 = QInputDialog.getText(self.MainWindow, "标题","请输入指定源IP地址:",QLineEdit.Normal, "*.*.*.*")
                rule = "src host "+filter
            elif item =="指定目的IP地址"  :
                filter,ok_2 = QInputDialog.getText(self.MainWindow, "标题","请输入指定目的IP地址:",QLineEdit.Normal, "*.*.*.*")
                rule= "dst host "+filter
            elif item =="指定源端口":
                filter,ok_3 = QInputDialog.getInt(self.MainWindow, "标题","请输入指定源端口:",80, 0, 65535)
                rule="src port "+str(filter)
            elif item =="指定目的端口":
                filter,ok_4 = QInputDialog.getInt(self.MainWindow, "标题","请输入指定目的端口:",80, 0, 65535)
                rule ="dst port "+str(filter)
            elif item =="指定协议类型" :
                filter,ok_2 = QInputDialog.getText(self.MainWindow, "标题","请输入指定协议类型:",QLineEdit.Normal, "icmp/arp/tcp/udp/igmp/...")
                rule =filter
            rule=rule.lower()
            self.filter = rule

    def postFilter(self):
        list = ["指定源IP地址","指定目的IP地址", "指定源端口","指定目的端口","指定协议类型"]   
        item, ok = QInputDialog.getItem(self.MainWindow, "捕获后过滤选项","规则列表", list, 1, False)
        if ok:
            if item=="指定源IP地址":
                filter,ok_1 = QInputDialog.getText(self.MainWindow, "标题","请输入指定源IP地址:",QLineEdit.Normal, "127.0.0.1")
                if ok_1:
                    self.postFilter_2(0,filter.lower())
            elif item =="指定目的IP地址"  :
                filter,ok_2 = QInputDialog.getText(self.MainWindow, "标题","请输入指定目的IP地址:",QLineEdit.Normal, "127.0.0.1")
                if ok_2:
                    self.postFilter_2(1,filter.lower())
            elif item =="指定源端口":
                filter,ok_3 = QInputDialog.getInt(self.MainWindow, "标题","请输入指定源端口:",80, 0, 65535)
                if ok_3:
                    self.postFilter_2(2,filter.lower())
            elif item =="指定目的端口":
                filter,ok_4 = QInputDialog.getInt(self.MainWindow, "标题","请输入指定目的端口:",80, 0, 65535)
                if ok_4:    
                    self.postFilter_2(3,filter.lower())
            elif item =="指定协议类型" :
                filter,ok_5 = QInputDialog.getText(self.MainWindow, "标题","请输入指定协议类型:",QLineEdit.Normal, "icmp/arp/tcp/udp/igmp/...")
                if ok_5:
                    self.postFilter_2(4,filter.lower())
                    
    def postFilter_2(self,index,filter):
        global displays
        displays = 0
        rows = self.tableWidget.rowCount()
        if index == 0:
            for row in range(rows):
                if str(self.packList[row].layer_3['src']).lower() != filter :
                    self.tableWidget.setRowHidden(row,True)
                else:
                    self.tableWidget.setRowHidden(row,False)
                    displays+=1
        elif index == 1:
            for row in range(rows):
                if str(self.packList[row].layer_3['dst']).lower() != filter :
                    self.tableWidget.setRowHidden(row,True)
                else:
                    self.tableWidget.setRowHidden(row,False)
                    displays+=1
        elif index == 2:
            for row in range(rows):
                if str(self.packList[row].layer_2['src']).lower() != filter :
                    self.tableWidget.setRowHidden(row,True)
                else:
                    self.tableWidget.setRowHidden(row,False)
                    displays+=1
        elif index == 3:
            for row in range(rows):
                if str(self.packList[row].layer_2['dst']).lower() != filter :
                    self.tableWidget.setRowHidden(row,True)
                else:
                    self.tableWidget.setRowHidden(row,False)
                    displays+=1
        else:
            for row in range(rows):
                filter = filter.upper()
                if self.packList[row].layer_2['name'] != filter and self.packList[row].layer_3['name'] != filter and \
                    self.packList[row].layer_1['name'] != filter :
                    self.tableWidget.setRowHidden(row,True)
                else:
                    self.tableWidget.setRowHidden(row,False)
                    displays+=1

    def Trace(self):
        row = self.tableWidget.currentRow()
        if self.packList[row].layer_2['name'] == 'TCP':
            list = ["根据源ip + 目的ip + 源端口 + 目的端口(进程间通信)","根据源ip+源端口(某进程产生的所有包)", "根据目的ip + 目的端口(某进程接受的所有包)"]   
            item, ok = QInputDialog.getItem(self.MainWindow, "TCP追踪","规则列表", list, 1, False)
            if ok:
                if item == "根据源ip + 目的ip + 源端口 + 目的端口(进程间通信)":
                    keys = 'tcptrace'
                elif item == "根据源ip+源端口(某进程产生的所有包)":
                    keys = 'tcpSdTrace'
                elif item == "根据目的ip + 目的端口(某进程接受的所有包)":
                    keys = 'tcpRcTrace'     
                mypacket = self.packList[row]
                trace = mypacket.layer_2[keys]
                for row in range(len(self.packList)):
                    if self.packList[row].layer_2[keys] == trace:
                        self.tableWidget.setRowHidden(row,False)
                    else:
                        self.tableWidget.setRowHidden(row,True)
        else:
            QtWidgets.QMessageBox.critical(None,"错误","非TCP相关协议，无法追踪")
    
    def Reset(self):
        for row in range(len(self.packList)):
            self.tableWidget.setRowHidden(row,False)
```

