import pcap
import os

class Packet():
    def __init__(self,raw_packet):
        self.bssid=[]
        self.fixed_param=""
        self.ssid=""
        self.raw_packet=raw_packet
        self.parseRadioTapHeader()
        self.parseBeaconFrame()
        self.parseParam()

    def parseRadioTapHeader(self):
        self.rt_header=self.raw_packet[:24]
        self.rt_header_revision=int(self.rt_header[0])
        self.rt_header_pad=int(self.rt_header[1])
        self.rt_header_len=int.from_bytes(self.rt_header[2:4],'little')
		
    def parseBeaconFrame(self):
        self.beacon_frame=self.raw_packet[self.rt_header_len:self.rt_header_len+24]
        self.frame_control_field=self.beacon_frame[0:2]
        self.duration=self.beacon_frame[2:4]
        self.dst_addr=":".join("%02X" % i for i in self.beacon_frame[4:10])
        self.src_addr=":".join("%02X" % i for i in self.beacon_frame[10:16])
        self.bss_id=":".join("%02X" % i for i in self.beacon_frame[16:22])
        self.seq_num=int.from_bytes(self.beacon_frame[22:24],'little')

    def parseParam(self):
        self.param=self.raw_packet[self.rt_header_len+24:]
        if len(self.param)==0: # no parameters
            return
        if self.param[8:10]!=b'\x64\x00': #tagged param
            self.tagged_param=self.raw_packet[self.rt_header_len+24:]
            self.parseTaggedParam()
        else:                     #fixed param + tagged param
            self.fixed_param=self.raw_packet[self.rt_header_len+24:self.rt_header_len+36]
            self.tagged_param=self.raw_packet[self.rt_header_len+36:]
            self.parseFixedParam()
            self.parseTaggedParam()

    def parseFixedParam(self):
        if self.fixed_param=="":
            return
        self.ts=int.from_bytes(self.fixed_param[:8],'little')
        self.intv=self.fixed_param[8:10]
        self.cap_info=int.from_bytes(self.fixed_param[10:12],'little')
    def parseTaggedParam(self):
        if len(self.tagged_param)==0:
            return
        self.tag_num=self.tagged_param[0]
        self.tag_len=int(self.tagged_param[1])
        try:
            self.ssid=self.tagged_param[2:2+self.tag_len].decode('utf-8')
        except:
            return

def printInfo(bssdata):
    os.system("clear")
    print("%s %20s %8s"%("BSSID","Beacons","ESSID"))
    for i in bssinfo.keys():
        print("%s %8s     %s"%(i,bssdata[i][0],bssdata[i][1]))

print("sniffing start")

bssinfo={}

sniffer=pcap.pcap(name="mon0",immediate=True,timeout_ms=50)

for ts,raw_pkt in sniffer:
    pkt=Packet(raw_pkt)
    try:
        if pkt.bss_id not in bssinfo.keys():
            if pkt.ssid=="":
                bssinfo[pkt.bss_id]=[1,"<legth: %d>"% pkt.tag_len]
            else:
                bssinfo[pkt.bss_id]=[1,pkt.ssid] # beacons, ESSID
        else:
            bssinfo[pkt.bss_id][0]+=1
        printInfo(bssinfo)
    except:
        continue
