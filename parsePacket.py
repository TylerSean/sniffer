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


