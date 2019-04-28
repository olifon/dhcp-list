# Find DHCP servers
View all connected DHCP servers on linux. Very useful when you try to find wrong DHCP servers.
For example: people that install routers with the LAN side on your network.
It gives a list of all DHCP servers by sending DISCOVER packages. The dhcp servers answer with OFFER PACKAGES.
When the client didn't receive any packages from him in 10 seconds, then the server is offline.
Compile with gcc, pthread and libpcap. Tested with mutiple ubuntu 18.04 with isc-dhcp-server on mutiple computers.
If you try to find the location of a DHCP server you can disconnect clients from your network until the server is offline.
