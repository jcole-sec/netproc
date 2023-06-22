#!/usr/bin/env python
 
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import os
import time
from pathlib import Path
from argparse import ArgumentParser, BooleanOptionalAction, RawTextHelpFormatter

# non-standard libs
import json
import psutil
from rich import print
from rich.progress import track
from rich.console import Console
from rich.table import Table

blank = '-'
AF_INET6 = getattr(socket, 'AF_INET6', object())

# Protocol Name translation
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}

def parseArguments():
    
    parser = ArgumentParser(
        description='netproc is a script that will:\n\
    * Retrieve a list of all currently running processes\n\
    * Display process details such as status, user, path, and parent process\n\
    * Display network connection details related to each process\n\
    ',
        formatter_class=RawTextHelpFormatter,
        epilog='For support, contact https://github.com/jcole-sec.\n ',
    )


    parser.add_argument(
        '-c', '--csv', 
        help='Enable output logging to .csv file.\nFile will be written to netproc_hostname_YYYYmmDD.HHMM.csv\n\
    ', 
        action=BooleanOptionalAction,
        default=True
    )

    parser.add_argument(
        '-j', '--json', 
        help='Enable output logging to .ndjson file.\nFile will be written to netproc_hostname_YYYYmmDD.HHMM.json\n\
    ', 
        action=BooleanOptionalAction,
        default=False
    )

    parser.add_argument(
        '-d', '--display', 
        help='Enable table display for process details.\n\
    ', 
        action=BooleanOptionalAction,
        default=False
    )
    return parser.parse_args()

def main():

    options = parseArguments()
    
    # set output file name details
    datetime = time.strftime('%Y%m%d.%H%M')
    hostname = socket.gethostname()

    if options.csv:
        outfilename  = f'netproc_{hostname}_{datetime}.csv'
    
    if options.json:
        outfilename  = f'netproc_{hostname}_{datetime}.ndjson'
        

    print('[*] Port and process enumeration initiated')

    with open(outfilename, 'at') as outfile:

        if options.csv:
            outfile.write('Proto, Local IP, Local Host, Local Port, Remote address,Remote host, Status,PID,Process name,PPID,PPID Name,User,Path,Command Line' + '\n')
        
        if options.display:
            # Rich table configution settings   
            table = Table(title=f'Process Data for: {hostname}')
            table.add_column("PID", style="cyan", no_wrap=True)
            table.add_column("Process Name", style="dim cyan")


        pdata = {}

        for c in track(psutil.net_connections(kind='inet')):

            # Process Id (Int)

            pdata['pid'] = str(c.pid)
            
            print(f'[-] enumerating network process: { pdata["pid"] }')

            # Protocol
            pdata['proto'] = str(proto_map[(c.family, c.type)])

            # Local Address
            pdata['lip'] = c.laddr.ip
            pdata['lport'] = c.laddr.port

            # Local Host Name
            try:                   
                pdata['lhost'] = socket.gethostbyaddr(c.laddr.ip)[0]
            except:
                pdata['lhost'] = blank

            # Remote Address
            if c.raddr:
                #raddr = "%s:%s" % (c.raddr)
                pdata['rip'] = c.raddr.ip
                pdata['rport'] = c.raddr.port
            else:
                pdata['rip'] = blank
                pdata['rport'] = blank

                        
            # Remote Host
            try:
                pdata['rhost'] =  socket.gethostbyaddr(c.raddr[0])[0]
            except:
                pdata['rhost'] = blank
            
            # Status
            pdata['status'] = c.status

            # Process Name
            try:
                pdata['pname'] = psutil.Process(c.pid).name()
            except:
                pdata['pname'] = blank

            # Parent Process Id (Int)
            try:
                pdata['ppid'] = psutil.Process(c.pid).ppid()
            except:
                pdata['ppid'] = blank
            
            # Parent Process Id Name
            try:
                pdata['ppid_name'] = psutil.Process(pdata['ppid']).name()
            except:
                pdata['ppid_name'] = blank

            # Process User
            try:
                pdata['puser'] = psutil.Process(c.pid).username()
            except:
                pdata['puser'] = blank

            # Process Path
            try:
                pdata['ppath'] = psutil.Process(c.pid).exe()
            except:
                pdata['ppath'] = blank
            
            # Command Line

            try:
                pdata['cmdline'] = ' '.join(str(each) for each in psutil.Process(c.pid).cmdline())
            except:
                pdata['cmdline'] = blank
            
            if options.csv:
                try:
                    #               'Proto, Local IP, Local Host, Local Port, Remote IP, Remote host, Remote Port, Status,PID,Process name,PPID,PPID Name,User,Path,Cmdline'
                    outfile.write(f"{pdata['proto']},{pdata['lip']},{pdata['lhost']},{pdata['lport']},{pdata['rip']},{pdata['rhost']},{pdata['rport']},{pdata['status']},{pdata['pid']},{pdata['pname']},{str(pdata['ppid'])},{pdata['ppid_name']},{pdata['puser']},{pdata['ppath']},{pdata['cmdline']}\n")        
                except:
                    outfile.write(f"{pdata['proto']},{pdata['lip']},{pdata['lhost']},{pdata['lport']},{pdata['rip']},{pdata['rhost']},{pdata['rport']},{pdata['status']},{pdata['pid']},-,-,-,-,-,-\n")
            
            if options.json:
                 outfile.write(json.dumps(pdata))
            
            if options.display:
                table.add_row(pdata['pid'], pdata['pname'])
        
        if options.display:
            console = Console()
            print('')
            console.print(table)
            print('')



    print('[*] Port and process enumeration complete')
    print(f'[*] Output written to file: {str(Path(outfilename))}')
 
 
if __name__ == '__main__':
    main()
