# Tlsfilter

A simple Linux program that continuously captures HTTPS traffic (using `libpcap`, port 443 TCP connections) on a specified network interface and extracts the version field from the TLS Client Hello packet as part of the TLS Handshake.

If the extracted version is less than a specified value then the program will log the connection source IP, destination IP and extracted version on a single line to console and to a file specified by the user.

The program will run until it recieves `SIGTERM` or `SIGINT`, ignoring all other signals (except those that can't be ignored, like `SIGKILL`).

## Synopsis
`
    $ ./tlsfilter ETH VERSION LOGFILE
`

`ETH` is the network interface (e.g. 'lo', 'eth0', 'wlan0', etc.) to capture on. `VERSION` is the minimum version (e.g. '1.2') for which the handshake is not logged. `LOGFILE` specifies the name of the file (e.g. 'tlsfilter.log') to which logs are written.

Example:

`
    $ ./tlsfilter eth0 1.2 tlsfilter.log
`
    
If you're not sure which version to use or which network interface, running the program with more/fewer arguments will show you:

    - The network interfaces available on the machine
    - The supported TLS versions of the program
    - How the application should be used
    
    
(These informations will be shown also when the version is incorrect or the device can't be oppened)

## Testing the program

Run the program, then perform a HTTPS request using curl, wget or browser. Check if the source ip, destination ip and  version has been logged in the specified log file and on the console.

To force a specific TLS version from the client side, you can use curl.

Example:

`
    $curl --tlsv1.0 --tls-max 1.0 https://cordero.me
`

## Recommended documentation

1. Man page of PCAP:
   https://www.tcpdump.org/manpages/pcap.3pcap.html
2. Programming with pcap:
   https://www.tcpdump.org/pcap.html
3. TLS Handshake:
   https://wiki.osdev.org/TLS_Handshake
