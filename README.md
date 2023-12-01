# NetTool
Small tool for doing stuff on networks <br>

## Specialized args
* `-findprinters` 
* `-onlynum`

# GET PRINTER SETTING PAGES
I mean the main thing it does is find the admin panel urls for printers that broadcast it on the network <br>
to do that:
```bash
sudo ./netTool -findprinters
```
the way it gets URLs from the packet data is really disgusting and horrible <br>
i should fix that sometime i think

# GET BASIC PACKET DATA
stuff like this:
```
==== PACKET ====
Packet capture length: 302
Packet total length 302
Packet Type IP
IP Header Length: 20
TOTAL HEADER SIZE 34
268 bytes from [IP_HERE] to [IP_HERE]
```
can be attained by running it without any specialized args
```bash
sudo ./netTool [other args that arent specialized args]
```