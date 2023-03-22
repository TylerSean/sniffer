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
    