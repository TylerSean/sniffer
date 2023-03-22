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

