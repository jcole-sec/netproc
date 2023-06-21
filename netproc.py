#!/usr/bin/env python
 
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import os
import psutil
import time
from pathlib import Path
from rich import print
from rich.progress import track

blank = '-'
AF_INET6 = getattr(socket, 'AF_INET6', object())

# Protocol Name translation
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}


def main():
    
    datetime = time.strftime('%Y%m%d.%H%M')
    hostname = socket.gethostname()
    outfilename  = f'{datetime}-{hostname}_netproc.csv'
    print('[*] Port and process enumeration initiated')

    with open(outfilename, 'at') as outfile:

        outfile.write('Proto, Local IP, Local Host, Local Port, Remote address,Remote host, Status,PID,Process name,PPID,PPID Name,User,Path' + '\n')

        for c in track(psutil.net_connections(kind='inet')):

            # Process Id (Int)
            pid = c.pid
            
            print(f'[-] enumerating network process: {str(c.pid)}')

            # Protocol
            proto = str(proto_map[(c.family, c.type)])

            # Local Address
            local_ip = c.laddr.ip
            local_port = c.laddr.port

            # Local Host Name
            try:                   
                lhost = socket.gethostbyaddr(local_ip)[0]
            except:
                lhost = blank

            # Remote Address
            raddr = ''
            if c.raddr:
                raddr = "%s:%s" % (c.raddr)
                        
            # Remote Host
            try:
                rhost =  socket.gethostbyaddr(c.raddr[0])[0]
            except:
                rhost = blank
            
            # Status
            status = str(c.status)

            # Process Name
            try:
                pname = str(psutil.Process(c.pid).name())
            except:
                pname = blank

            # Parent Process Id (Int)
            try:
                parpid = psutil.Process(c.pid).ppid()
            except:
                parpid = blank
            
            # Parent Process Id Name
            try:
                ppid_name = str(psutil.Process(parpid).name())
            except:
                ppid_name = blank

            # Process User
            try:
                puser = str(psutil.Process(c.pid).username())
            except:
                puser = blank

            # Process Path
            try:
                ppath = str(psutil.Process(c.pid).exe())
            except:
                ppath = blank

            try:
                #               'Proto, Local IP, Local Host, Local Port, Remote address,Remote host, Status,PID,Process name,PPID,PPID Name,User,Path'
                outfile.write(f'{proto},{local_ip},{lhost},{local_port},{str(raddr)},{rhost},{status},{str(c.pid)},{pname},{str(parpid)},{ppid_name},{puser},{ppath}\n')        
            except:
                outfile.write(f'{proto},{local_ip},{lhost},{local_port},{str(raddr)},{rhost},{status},{str(c.pid)},-,-,-,-,-\n')

    print('[*] Port and process enumeration complete')
    print(f'[*] Output written to file: {str(Path(outfilename))}')
 
 
if __name__ == '__main__':
    main()
