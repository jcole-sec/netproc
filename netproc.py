#!/usr/bin/env python
 
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import os
import psutil
import time
from pathlib import Path
from rich import print
from rich.progress import track

AD = '-'
AF_INET6 = getattr(socket, 'AF_INET6', object())

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

        outfile.write('Proto,Local address, Local host, Remote address,Remote host, Status,PID,Process name,PPID,PPID Name,User,Path' + '\n')

        for c in track(psutil.net_connections(kind='inet')):

            print(f'[-] enumerating network process: {str(c.pid or AD)}')

            # Protocol
            proto = str(proto_map[(c.family, c.type)])

            # Local Address
            laddr = "%s:%s" % (c.laddr)

            # Local Host
            try:                   
                lhost = socket.gethostbyaddr(c.laddr[0])[0] or AD
            except:
                lhost = '-'

            # Remote Address
            raddr = ''
            if c.raddr:
                raddr = "%s:%s" % (c.raddr)
                        
            # Remote Host
            try:
                rhost =  socket.gethostbyaddr(c.raddr[0])[0] or AD
            except:
                rhost = '-'
            

            # Status

            # Process Id


            # Parent Process Id
            parpid = str(psutil.Process(c.pid).ppid())
            
            # Parent Process Id Name
            ppid_name = str(psutil.Process(parpid).name())

            # User
            user = str(psutil.Process(c.pid).username())


            try:
                outfile.write(f'{proto},{str(laddr)},{str(lhost)},{str(raddr or AD)},{str(rhost or AD)},{(c.status)},{str(c.pid or AD)},\
                {str(psutil.Process(c.pid).name())},{parpid},{ppid_name},{user},{str(psutil.Process(c.pid).exe())}\n')        
            except:
                outfile.write(f'{str(proto_map[(c.family, c.type)])},{str(laddr)},{str(lhost)},{str(raddr or AD)},{str(rhost or AD)},{str(c.status)},{str(c.pid or AD)},-,-,-,-,-\n')

    print('[*] Port and process enumeration complete')
    print(f'[*] Output written to file: {str(Path(outfilename))}')
 
 
if __name__ == '__main__':
    main()
