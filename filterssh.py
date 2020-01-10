#!/bin/bash/python2.7

from scapy.all import *
import os, commands

load_layer('ssh')
bind_layers(TCP, SSH)
bind_layers(TCP, SSH)
bind_layers(SSH, SSHMessage)
bind_layers(SSHMessage, SSHKexInit, {'type': 0x14})
bind_layers(SSHMessage, SSHDisconnect, {'type': 0x01})
bind_layers(SSH, SSHEncryptedPacket)
filter ='tcp'

def checkSSH(pkg):
    if pkg.haslayer(SSHIdent):
        port = str(pkg[TCP].dport)
        ip = str(pkg[IP].dst)
        cmd = 'ipset -T drop_ssh ' + ip
        set = 'ipset -A drop_ssh ' + ip
        print('<--- SSH detected on port: ' + port + ' from IP: ' + ip + '! --->')
        res = commands.getoutput(cmd)
        if str(ip + ' is NOT in set drop_ssh.') in res:
            os.system(set)
            print('<--- IP ' + ip + ' is BLOCKED! --->')
            exit()
        else: print('<--- IP ' + ip + ' already in list drop_ssh! --->')
    else:
        print(filter + ': ' + str(pkg[IP].src) + ':' + str(pkg[TCP].sport) + ' => ' + str(pkg[IP].dst) + ':' + str(pkg[TCP].dport))

sniff(iface='eth0', filter=filter, prn=checkSSH)
