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