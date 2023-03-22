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
 
