# netproc

Retrieve socket usage and associated process details. 

Credit to Giampaolo Rodola's netstat.py for project seed.


Compile to exe

```
pyinstaller.exe --onefile --windowed --icon=assets/Kyo-Tux-Delikate-Network.ico netproc.py
```

icon image source: https://www.iconarchive.com/show/delikate-icons-by-kyo-tux/network-icon.html, 
llicense reference: https://www.iconarchive.com/about.html


Build
```
pyinstaller .\netproc.py --onefile --icon .\assets\Kyo-Tux-Delikate-Network.ico
```
or
```
python3 build.py
```

### Demo
```
python .\netproc.py -d --no-tsv -p
```