from scapy.all import *
import os

load_layer('ssh')
bind_layers(TCP, SSH, dport=22)
bind_layers(TCP, SSH, sport=22)
bind_layers(SSH, SSHMessage)
bind_layers(SSHMessage, SSHKexInit, {'type': 0x14})
bind_layers(SSHMessage, SSHDisconnect, {'type': 0x01})
bind_layers(SSH, SSHEncryptedPacket)
filter ='tcp and src host 178.128.242.4'

def checkSSH(pkg):
    if pkg.haslayer(SSHIdent):
        port = str(pkg[TCP].dport)
        ip = str(pkg[IP].src)
        cmd = 'iptables -A OUTPUT -p tcp -d '+ ip + ' --dport ' + port + ' -j DROP'
        print('!!! SSH DETECTED on PORT: ' + port + ' from IP: ' + ip + ' !!!')
        #res = os.system(cmd)
        return cmd
    else: print(str(pkg[IP].proto) + ': ' + str(pkg[IP].src) + ':' + str(pkg[TCP].sport) + ' => ' + pkg[IP].dst + ':'+ str(pkg[TCP].dport))

sniff(iface='eth0', filter=filter, prn=checkSSH)







