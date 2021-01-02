import subprocess
import os
import re
from netsuit.log import log_sys

class wDev():
    def __init__(self,ifaceName):
        self.ifaceName = ifaceName
        self.isManaged = self.isNetManaged(ifaceName)
        self.curChannel = 0
        cur_info = "iw %s info" % ifaceName
        res_tmp = subprocess.Popen(cur_info,shell=True,stdout=subprocess.PIPE)
        for line in res_tmp.stdout.readlines():
            line_tmp = line.decode('utf-8')
            if re.match('\sifindex',line_tmp):
                self.ifindex = line_tmp.split(' ')[-1].strip()
            if re.match("\saddr",line_tmp):
                self.realMac = line_tmp.split(' ')[-1].strip()
            if re.match('\stype',line_tmp):
                self.typeMode = line_tmp.split(' ')[-1].strip()
            if re.match('\schannel',line_tmp):
                self.curChannel = line_tmp.split(' ')[1].strip()
        res_tmp.stdout.close()
    def isNetManaged(self,ifaceName):
        nmcli_status = "nmcli device status | grep %s | wc -l" % ifaceName
        res_tmp = subprocess.Popen(nmcli_status,shell=True,stdout=subprocess.PIPE)
        res = res_tmp.stdout.readline().decode('utf-8')
        res_tmp.stdout.close()
        return int(res[0])
    def removeNetManaged(self):
        nmcli_remove = "nmcli device set %s managed no" % self.ifaceName
        os.system(nmcli_remove)
        self.isManaged = 0
    def addNetManaged(self):
        nmcli_add = "nmcli device set %s managed yes" % self.ifaceName
        os.system(nmcli_add)
        self.isManaged = 1
    def enterMonitor(self):
        if self.isManaged == 1:
            self.removeNetManaged()
        enterMon = "ip link set %s down;iw dev %s set monitor none;ip link set %s up" % (self.ifaceName, self.ifaceName, self.ifaceName)
        self.typeMode = "monitor"
        os.system(enterMon)

    def leaveMonitor(self):
        if self.isManaged == 0:
            self.addNetManaged()
        leaveMon = "ip link set %s down;iw dev %s set type managed;ip link set %s up" % (self.ifaceName, self.ifaceName, self.ifaceName)
        self.typeMode = "managed"
        os.system(leaveMon)
    
    def changeChannel(self,curChannel):
        self.curChannel = int(curChannel)
        changeChan = "iw dev %s set channel %d" % (self.ifaceName, self.curChannel)
        os.system(changeChan)

    def __repr__(self): 
        pr_content = "dev iface {}:\n\t isNetManaged {}\n\t mac addr {}\n\t type {}\n\t channel {}".format(self.ifaceName,self.isManaged
            ,self.realMac,self.typeMode,self.curChannel)
        return pr_content

class wDevs():
    def __init__(self):
        self.__wDevs = []
        wIfaces = "ls -d /sys/class/net/*/phy80211 | cut -d/ -f5"
        res_tmp = subprocess.Popen(wIfaces,shell=True,stdout=subprocess.PIPE)
        for dev in res_tmp.stdout.readlines():
            self.__wDevs.append(wDev(dev.decode('utf-8').strip())) 
    def showDevs(self):
        for i in self.__wDevs:
            print(i)
    
    def __getitem__(self,k):
        try:
            return self.__wDevs[int(k)]
        except IndexError as err:
            print("no such device")
            log_sys.critical("error: get device {}".format(err))
            raise SystemExit
    def __len__(self):
        return len(self.__wDevs)
