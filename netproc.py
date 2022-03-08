#!/usr/bin/env python
 
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import os
import psutil
import time
 

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
    outfile  = datetime + '-' + hostname + '_netproc.csv'
    print('--- Port and process enumeration initiated ---')
    with open(outfile, 'at') as outfile:
        outfile.write('Proto,Local address, Local host, Remote address,Remote host, Status,PID,Process name,PPID,PPID Name,User,Path' + '\n')
        for c in psutil.net_connections(kind='inet'):
            print('enumerating network process: ' + str(c.pid or AD))
            laddr = "%s:%s" % (c.laddr)
            raddr = ''
            if c.raddr:
                raddr = "%s:%s" % (c.raddr)
            try:
                try:                   
                    lhost = socket.gethostbyaddr(c.laddr[0])[0] or AD
                except:
                    lhost = '-'
                try:
                    rhost =  socket.gethostbyaddr(c.raddr[0])[0] or AD
                except:
                    rhost = '-'
                parpid = psutil.Process(c.pid).ppid()
                outfile.write(str(proto_map[(c.family, c.type)]) + ',' + str(laddr) + ',' + str(lhost) + ','+ str(raddr or AD) + ','+ str(rhost or AD) + ',' + str(c.status) + ',' + str(c.pid or AD) + ',' + \
                str(psutil.Process(c.pid).name()) + ',' + str(parpid) + ',' + str(psutil.Process(parpid).name()) + ',' + str(psutil.Process(c.pid).username()) + ','+ str(psutil.Process(c.pid).exe()) + '\n')        
            except:
                outfile.write(str(proto_map[(c.family, c.type)]) + ',' +str(laddr) + ',' + str(lhost) + ','+ str(raddr or AD) + ','+ str(rhost or AD) + ',' + str(c.status) + ',' + str(c.pid or AD) + ',-,-,-,-,-' + '\n')
    print('--- Port and process enumeration complete ---')
    input('output written to file: ' + str(os.path.abspath(outfile)))
 
 
if __name__ == '__main__':
    main()
