#! /bin/bash/python2.7
#  -*- coding: UTF-8 -*-
from scapy.all import *
import subprocess, os

load_layer('ssh')
bind_layers(TCP, SSH, dport=22)
bind_layers(TCP, SSH, sport=22)
bind_layers(SSH, SSHMessage)
bind_layers(SSHMessage, SSHKexInit, {'type': 0x14})
bind_layers(SSHMessage, SSHDisconnect, {'type': 0x01})
bind_layers(SSH, SSHEncryptedPacket)
filter ='tcp'

def checkSSH(pkg):
    if pkg.haslayer(SSHIdent):
        port = str(pkg[TCP].dport)
        ip = str(pkg[IP].src)
        #cmd = 'iptables -A FORWARD -p tcp -m '+ ip + ' --dport ' + port + ' -j DROP'
        #cmd = 'ipset -T drop_ssh ' + ip
        set = 'ipset -A drop_ssh ' + ip
        #res = os.system(cmd)
        print('--- SSH detected on port: ' + port + ' from IP: ' + ip + '! ---')
        res = subprocess.Popen(['ipset -T drop_ssh ' + ip ], stdout=subprocess.PIPE, shell=True)
        output = res.stdout.read()
        (out, err) = res.communicate()
        p_status = res.wait()
        print (output)
        print (out)
        print (err)
        if ip + ' is NOT in set drop_ssh.' in out:
            os.system(set)
            print('--- IP ' + ip + ' is BLOCKED! ---')
        else: print('--- IP ' + ip + ' already in list drop_ssh! ---')
    else:
        print(filter + ': ' + str(pkg[IP].src) + ':' + str(pkg[TCP].sport) + ' => ' + pkg[IP].dst+':'+ str(pkg[TCP].dport))

sniff(iface='eth0', filter=filter, prn=checkSSH)
