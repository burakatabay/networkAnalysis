import netifaces as ni
from PyQt4 import QtGui
from scapy.all import *
import getInfo
from screen import Ui_MainWindow
from threading import Thread
from sniff import PacketSniffer
import datetime


class Monitor():
    def __init__(self):
        self.gtnf = getInfo.ArpSpoof()
        ui.comboBox.addItems(ni.interfaces())
        ui.comboBox.activated.connect(self.getNetworkInfo)
        ui.btn_sniffer.clicked.connect(self.onSwitch)
        ui.table_network.clicked.connect(self.dataMessage)
        self.ps = PacketSniffer()

    def ipmacvendor(self):
        data = self.gtnf.get_sc()
        i = 0
        for dt in data:
            ui.table_vendor.insertRow(i)
            ui.table_vendor.setItem(i, 0, QtGui.QTableWidgetItem(str(data[i][0])))
            ui.table_vendor.setItem(i, 1, QtGui.QTableWidgetItem(str(data[i][1])))
            ui.table_vendor.setItem(i, 2, QtGui.QTableWidgetItem(str(data[i][2])))
            i += 1

    def getNetworkInfo(self):
        iface = ui.comboBox.currentText()
        gi = getInfo.Information()
        ip, mac, gw, bcast, nmask = gi.networkInfo(iface)
        ui.lbl_yourip.setText(ip)
        ui.lbl_yourmac.setText(mac)
        ui.lbl_gatewayip.setText(gw)
        ui.lbl_bcast.setText(bcast)
        ui.lbl_nmask.setText(nmask)
        Thread(target=self.ipmacvendor, daemon=True).start()


    def dataMessage(self):
        i = ui.table_network.currentRow()
        j = ui.table_network.currentColumn()
        print(i, j)
        data = ui.table_network.itemAt(i, j)
        msg = QtGui.QMessageBox()
        msg.setIcon(QtGui.QMessageBox.Information)
        msg.setText(data.text())
        msg.setInformativeText("This is additional information")
        msg.setWindowTitle("MessageBox demo")
        msg.setDetailedText("The details are as follows:")
        msg.exec_()

    def append(self):
        i = 0
        j = 0
        while self.ps.cookie:
            packet = self.ps.run()
            try:
                packet.time = datetime.datetime.fromtimestamp(packet.time)
                if packet.packetype == "TCP":
                    ui.table_network.insertRow(i)
                    ui.table_network.setItem(i, 0, QtGui.QTableWidgetItem(str(packet.packetdata)))
                    ui.table_network.setItem(i, 1, QtGui.QTableWidgetItem(str(packet.time)))
                    ui.table_network.setItem(i, 2, QtGui.QTableWidgetItem(str(packet.source_ip)))
                    ui.table_network.setItem(i, 3, QtGui.QTableWidgetItem(str(packet.source_mac)))
                    ui.table_network.setItem(i, 4, QtGui.QTableWidgetItem(str(packet.source_port)))
                    ui.table_network.setItem(i, 5, QtGui.QTableWidgetItem(str(packet.destination_ip)))
                    ui.table_network.setItem(i, 6, QtGui.QTableWidgetItem(str(packet.destination_mac)))
                    ui.table_network.setItem(i, 7, QtGui.QTableWidgetItem(str(packet.destination_port)))
                    ui.table_network.setItem(i, 8, QtGui.QTableWidgetItem(str(packet.packetraw)))

                    i += 1
                elif packet.packetype == "DNS":
                    print('[*] DNS Packet found.')
                    ui.table_network_dns.insertRow(j)
                    ui.table_network_dns.setItem(j, 0, QtGui.QTableWidgetItem(str(packet.time)))
                    ui.table_network_dns.setItem(j, 1, QtGui.QTableWidgetItem(str(packet.source_ip)))
                    ui.table_network_dns.setItem(j, 2, QtGui.QTableWidgetItem(str(packet.packetquery)))
                    j += 1
            except:
                pass

    def onSwitch(self):
        self.ps.cookie = True
        Thread(target=self.append, daemon=True).start()


if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    mon = Monitor()
    MainWindow.show()
    sys.exit(app.exec_())
