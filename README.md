# Nmap-Reference-Guide #
Nmap Reference Guide


# Name #

nmap - network exploration tool and security / port scanner

# Command #

nmap [<Scan Type> ...] [<Options>] {<scanning destination>}

# Description #

** Note **: This document describes the Nmap version 4.50. The latest documentation is provided in English [https://nmap.org/book/man.html](https://nmap.org/book/man.html).

Nmap ( "Network Mapper (Network Mapper)") is a network exploration and security auditing tool for an open source. Its design goal is to rapidly scan large networks, of course, use it to scan a single host no problem. Nmap novel way to use raw IP packets to detect which host on the network, those hosts to provide what services (application name and version) those services running on what operating system (including version information), they use what types of packets filters / firewalls, and a bunch of other functions. While Nmap is used for security audits, many system administrators and network administrators can also use it to do some routine work, such as viewing information across the network, managing service upgrade plans, and operational monitoring hosts and services.

Nmap scan output is a list of targets, as well as supplemental information for each goal, as to what information depends on the option used. "Port table of interest" is the key. That table lists the port number, protocol, service name and status. State may be open (open), Filtered (filtered), Closed (closed), or Unfiltered (unfiltered). Open (open) application on the port means that the target machine is listening for connections / packets. filtered means that a firewall, filter, or other network obstacle (filtered) blocked the port is accessed, Nmap does not know it is open (open) or closed (closed). closed (closed) port no application listening on it, but they may be open at any time. When the port responds to Nmap probe, but Nmap can not determine whether they are closed or open, these ports is considered to be unfiltered (unfiltered) If Nmap reports the state combinations open | filtered and closed | When filtered, it means Nmap can not determine which of the port in the two states. When the required version of the probe, the port table may also include software version information. When (-sO) requires IP protocol scanning, Nmap provides IP protocol on information rather than supported port is listening.

In addition to the port table of interest, Nmap can provide further information about the target machine, including reverse domain name, operating system guesses, device types, and MAC address.

1 "A typical Nmap Scan" a typical embodiment shown as Nmap scan. In this case, the only option is -A, used for the operating system and version detection, -T4 speeds execution, followed by two goals hostname.

** Example 1. A typical Nmap scan **

	# Nmap -A -T4 scanme.nmap.org
	
	Nmap scan report for scanme.nmap.org (74.207.244.221)
	Host is up (0.029s latency).
	rDNS record for 74.207.244.221: li86-221.members.linode.com
	Not shown: 995 closed ports
	PORT STATE SERVICE VERSION
	22 / tcp open ssh OpenSSH 5.3p1 Debian 3ubuntu7 (protocol 2.0)
	| Ssh-hostkey: 1024 8d: 60: f1: 7c: ca: b7: 3d: 0a: d6: 67: 54: 9d: 69: d9: b9: dd (DSA)
	| _2048 79: f8: 09: ac: d4: e2: 32: 42: 10: 49: d3: bd: 20: 82: 85: ec (RSA)
	80 / tcp open http Apache httpd 2.2.14 ((Ubuntu))
	| _http-title: Go ahead and ScanMe!
	646 / tcp filtered ldp
	1720 / tcp filtered H.323 / Q.931
	9929 / tcp open nping-echo Nping echo
	Device type: general purpose
	Running: Linux 2.6.X
	OS CPE: cpe: / o: linux: linux_kernel: 2.6.39
	OS details: Linux 2.6.39
	Network Distance: 11 hops
	Service Info: OS: Linux; CPE: cpe: / o: linux: kernel
	
	TRACEROUTE (using port 53 / tcp)
	HOP RTT ADDRESS
	[Cut first 10 hops for brevity]
	11 17.65 ms li86-221.members.linode.com (74.207.244.221)
	
	Nmap done: 1 IP address (1 host up) scanned in 14.40 seconds

# # Summary of Options
When Nmap runs without options, this option will be output summary, the latest version here [http://www.insecure.org/nmap/data/nmap.usage.txt](http://www.insecure. org / nmap / data / nmap.usage.txt). It helps people remember the most common options, but not a substitute for the rest of this manual-depth documentation of some obscure options are not even here.

	Usage: nmap [Scan Type (s)] [Options] {target specification}
	TARGET SPECIFICATION:
	    Can pass hostnames, IP addresses, networks, etc.
	    Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0-255.0-255.1-254
	    -iL <inputfilename>: Input from list of hosts / networks
	    -iR <num hosts>: Choose random targets
	    --exclude <host1 [, host2] [, host3], ...>: Exclude hosts / networks
	    --excludefile <exclude_file>: Exclude list from file
	HOST DISCOVERY:
	    -sL: List Scan - simply list targets to scan
	    -sP: Ping Scan - go no further than determining if host is online
	    -P0: Treat all hosts as online - skip host discovery
	    -PS / PA / PU [portlist]: TCP SYN / ACK or UDP discovery probes to given ports
	    -PE / PP / PM: ICMP echo, timestamp, and netmask request discovery probes
	    -n / -R: Never do DNS resolution / Always resolve [default: sometimes resolve]
	SCAN TECHNIQUES:
	    -sS / sT / sA / sW / sM: TCP SYN / Connect () / ACK / Window / Maimon scans
	    -sN / sF / sX: TCP Null, FIN, and Xmas scans
	    --scanflags <flags>: Customize TCP scan flags
	    -sI <zombie host [: probeport]>: Idlescan
	    -sO: IP protocol scan
	    -b <ftp host relay>: FTP bounce scan
	PORT SPECIFICATION AND SCAN ORDER:
	    -p <port ranges>: Only scan specified ports
	    Ex: -p22; -p1-65535; -p U: 53,111,137, T: 21-25,80,139,8080
	    -F: Fast - Scan only the ports listed in the nmap-services file)
	    -r: Scan ports consecutively - do not randomize
	SERVICE / VERSION DETECTION:
	    -sV: Probe open ports to determine service / version info
	    --version-light: Limit to most likely probes for faster identification
	    --version-all: Try every single probe for version detection
	    --version-trace: Show detailed version scan activity (for debugging)
	OS DETECTION:
	    -O: Enable OS detection
	    --osscan-limit: Limit OS detection to promising targets
	    --osscan-guess: Guess OS more aggressively
	TIMING AND PERFORMANCE:
	    -T [0-6]: Set timing template (higher is faster)
	    --min-hostgroup / max-hostgroup <msec>: Parallel host scan group sizes
	    --min-parallelism / max-parallelism <msec>: Probe parallelization
	    --min_rtt_timeout / max-rtt-timeout / initial-rtt-timeout <msec>: Specifies probe round trip time.
	    --host-timeout <msec>: Give up on target after this long
	    --scan-delay / - max_scan-delay <msec>: Adjust delay between probes
	FIREWALL / IDS EVASION AND SPOOFING:
	    -f; --mtu <val>: fragment packets (optionally w / given MTU)
	    -D <decoy1, decoy2 [, ME], ...>: Cloak a scan with decoys
	    -S <IP_Address>: Spoof source address
	    -e <iface>: Use specified interface
	    -g / - source-port <portnum>: Use given port number
	    --data-length <num>: Append random data to sent packets
	    --ttl <val>: Set IP time-to-live field
	    --spoof-mac <mac address, prefix, or vendor name>: Spoof your MAC address
	OUTPUT:
	    -oN / -oX / -oS / -oG <file>: Output scan results in normal, XML, s | <rIpt kIddi3, and Grepable format, respectively, to the given filename.
	    -oA <basename>: Output in the three major formats at once
	    -v: Increase verbosity level (use twice for more effect)
	    -d [level]: Set or increase debugging level (Up to 9 is meaningful)
	    --packet-trace: Show all packets sent and received
	    --iflist: Print host interfaces and routes (for debugging)
	    --append-output: Append to rather than clobber specified output files
	    --resume <filename>: Resume an aborted scan
	    --stylesheet <path / URL>: XSL stylesheet to transform XML output to HTML
	    --no_stylesheet: Prevent Nmap from associating XSL stylesheet w / XML output
	MISC:
	    -6: Enable IPv6 scanning
	    -A: Enables OS detection and Version detection
	    --datadir <dirname>: Specify custom Nmap data file location
	    --send-eth / - send-ip: Send packets using raw ethernet frames or IP packets
	    --privileged: Assume that the user is fully privileged
	    -V: Print version number
	    -h: Print this help summary page.
	EXAMPLES:
	    nmap -v -A scanme.nmap.org
	    nmap -v -sP 192.168.0.0/16 10.0.0.0/8
	    nmap -v -iR 10000 -P0 -p 80

# # Target Description

In addition to the options, all appear on the Nmap command line are treated as description of the target host. The simplest case is to specify a target IP address or host name.

Sometimes you want to scan the whole network of adjacent hosts. To do this, Nmap supports CIDR-style address. You can attach a / <numbit> behind a IP address or host name, Nmap will scan all IP addresses having the reference and <numbit> All the same IP address or host bits. For example, 192.168.10.0 / 24 scanning will 192.168.10.0 (binary format: 1,100,000,010,101,000 0,000,101,000,000,000): between 256 and host 192.168.10.255 (11000000 10101000 00001010 11111111 in binary format). 192.168.10.40/24 will do the same thing. Assume that the host scanme.nmap.org IP address is 205.217.153.62, scanme.nmap.org/16 scan 65,536 IP addresses between 205.217.0.0 and 205.217.255.255. Is the minimum value allowed / 1, which will scan a half Internet. It is the maximum value / 32, which will scan the host or IP address, since all bits are fixed.

CIDR flag is very simple but sometimes not flexible enough. For example, you might want to scan 192.168.0.0/16, but skip any IP address ending with .0 or .255 because they are usually broadcast address. Nmap supports this through octet address range scanning You can use a comma separated list of numbers or ranges to specify its range for each octet of the IP address. For example, 192.168.0-255.1-254 will be skipped in the range of .255 to 0.01 and end address. Need not be limited to the scope of the last eight: 0-255.0-255.13.37 will scan all addresses ending at 13.37 within the range of the entire Internet. This scanning may be useful to a wide range of Internet research.

IPv6 addresses can only be specified with the standard IPv6 address or host name. CIDR and octet range that does not support IPv6, since they are almost useless for IPv6.

Nmap command accepts a plurality of host instructions, they need not be the same type. Command ** nmap scanme.nmap.org 192.168.0.0/8 10.0.0,1,3-7.0-255 ** and will perform as you expect.

While targets are usually specified on the command line, the following options are also available to control target selection:

** - iL <inputfilename> (input from the list) **

Description read target from * <inputfilename> * in. At the command line, enter the host name of a bunch of clumsy, but often need. For example, your DHCP server might export a list of 10,000 current leases, and you want them to be scanned. If you are not using unauthorized static IP to locate a host, perhaps you want to scan all IP addresses. As long as generate a list of hosts to scan, with the file name as an option -iL passed Nmap. Item in the list may be in any format Nmap on the command line received (IP address, hostname, CIDR, IPv6, or octet range). Each one must be separated by one or more spaces, tabs, or new. If you want Nmap to read from a list of standard input rather than an actual file, you can use a hyphen (-) as the filename.

** - iR <hostnum> (randomly selected target) **

For surveys and studies within the scope of the Internet, you might want to randomly select the target. * <Hostnum> * option tells Nmap how many IP generation. Undesirable as specific private IP multicast address is not assigned or automatically skipped. 0 means that the scan options endless. Remember, some of the network might be very cold and complained to unauthorized scans. Use this option at your own risk! If a rainy day in the afternoon, you feel really bored, try this command nmap -sS -PS80 -iR 0 -p 80 to find some random web browsing.

** - exclude <host1 [, host2] [, host3], ...> (negative host / network) **

If there are a host or network is not your goals you specify the scanning range, then use this option to add a comma-separated list of excluded them. The list with normal Nmap syntax, it may include a host name, CIDR, etc. octet range. When the server you want to scan the network contains mission critical, known port scan is a strong reaction system or custody of others subnets, it might be useful.

** - excludefile <excludefile> (exclusion list file) **

This --exclude options and functions the same, but the goal is to negative line breaks, spaces, or tab-delimited * <excludefile> * provided, instead of the input on the command line.

# # Host found

One of the first steps in any network exploration mission is to put a set of IP range (the range is sometimes huge) is reduced to an activity or host that you are interested in. Each port scan each IP is very slow, usually it is not necessary. Of course, what kind of a host of interest to you depends on the scan purposes. Network management may only be interested in running a particular service host, and those engaged in security is probably interested in a toilet, as long as it has an IP address :-). A system administrator may only use Ping to locate hosts on the Internet, while an external penetration testers may brains in various ways trying to break the blockade of the firewall.

As the demand for a wide variety of host discovery, Nmap provides a laundry list of options to customize your needs. Host found sometimes called ping scan, but it goes far beyond the simple sending ICMP echo request packets with the ping tool known around the world. Users can use the list by scanning (-sl) or by closing step ping ping (-P0) to skip, multiple ports may be used the TCP SYN / ACK, UDP and ICMP and play any combination. The purpose of the probe is to obtain a response to show if an IP address is active (is being used by a host or network device). On many networks, at a given time, often only a small part of the IP address is active. In this case based on RFC1918 private address space such as 10.0.0.0/8 particularly prevalent. That network has 16 million IP, but I have seen some companies use it even 1000 machines are not. Host discovery can find those machines scattered on the IP address of the ocean.

If the option is not given host found, Nmap sends a TCP ACK packet to port 80 and an ICMP echo request to each target machine. An exception is the ARP scan for any target machine on the LAN. For unprivileged UNIX shell users, use connect () system call will send the same effect as a SYN packet rather than the default behavior and use these ACK -PA -PE options. When scanning the local area network, the host found generally adequate, but for the safety audit, recommended a more thorough probe.

-P option (for selecting the type of ping) may be used in combination. You can use different TCP ports / flags and ICMP codes sent many probe packets to increase the firewall to penetrate heavily defended opportunities. Another point to note is that even if you specify other -P * options, ARP discovery (-PR) for the target on local area networks is the default behavior, because it is always faster and more efficiently.

The following options control host discovery.

** - sL (list sweep) **

Scan the list is degenerate form of host discovery, it only lists each host on the specified network does not send any message to the target host. By default, Nmap still host reverse DNS to get their names. Useful information can give a simple host name is often surprising. For example, fw.chi.playboy.com Playboy Chicago office firewall. Nmap also reports the total number of final IP addresses. Scan the list may well make sure you have the correct destination IP. If the host name surprise you, then it is worth further examination to prevent mistakenly scan the network to other organizations.

Now just print a list of target host, like a number of other advanced features such as port scanning, OS detection, or Ping Scan option no. If you want to turn off ping scanning while still performing such advanced features, read introduction to -P0 options.

** - sP (Ping Scan) **

This option tells Nmap only perform a ping scan (host discovery), then print out the host to respond to those scans. Without further testing (e.g., port scanning probe or the operating system). This is more positive than the list scan, and a list of frequently used scan the same purpose. It can get a little information about the target network without being particularly noticed. For an attacker to learn how many hosts are running an IP host name and provided a list of scanning is often more valuable than that.

System administrators often like this option. It can easily come to have many machines are running on the network or to monitor whether the server is running. Often people call it carpet-ping, it is more reliable than the ping broadcast address because many hosts do not respond to the broadcast request.

-sP Options By default, send an ICMP echo request and a TCP port 80 packets to. If a non-privileged user, it sends a SYN packet (with the connect () system call) to port 80 on the target machine. When the target machine to scan the privileged user local area network, it will send ARP requests (-PR),, unless the --send-ip option. -sP option can be used to detect and find any type except -P0) of -P * options combined in order to achieve greater flexibility. Once the use of any probe type and port options, the default detection (ACK and echo request) will be covered. When the firewall is located between the heavily defended running Nmap source host and destination networks, it is recommended to use those advanced options. Otherwise, when the firewall is captured and discarded the packet or the probe response packet, some hosts can not be detected.

** - P0 (no ping) **

This option completely skip the Nmap discovery stage. Nmap usually determined by its high intensity during scanning running machine. By default, Nmap only running on the computers detect high strength such as port scans, version detection, or OS detection. Prohibition will host Nmap to find each specified destination IP address scanning required by -P0. So if a class specified on the command line target address space B (/ 16), 65,536 IP addresses are scanned. -P0 second character is the number zero, not the letter O. And list sweep like bypass the normal host discovery, but not to print a list of targets, but continue to perform the required functions, as if each IP are active.

** - PS [portlist] (TCP SYN Ping) **

This option sends an empty TCP packet is set SYN flag. The default destination port 80 (by changing nmap.h) configured DEFAULT-TCP-PROBE-PORT value of the file, but a different port may be designated as an option. Even port can specify a list separated by commas (e.g. -PS22,23,25,80,113,1050,35000), in this case, each port will be concurrently scanned.

SYN flag to tell someone you are trying to establish a connection. Usually the target port is closed, a RST (reset) packet will be sent back. If it happens that the port is open, the target will be the second step TCP three-way handshake, the response to a SYN / ACK TCP packet. The machine will then run Nmap stifle the connection being established, rather than sending a RST ACK packet, otherwise, will establish a full connection. RST packets is running Nmap Nmap machine itself rather than the response because it received SYN / ACK surprise.

Nmap does not care about the port open or closed. Whether RST or SYN / ACK response tell Nmap that the host is running.

On UNIX machines, only the privileged user root is generally able to send and receive raw TCP packets. So as a workaround for non-privileged user, Nmap will make a system call connect () for each target host, it will send a SYN packet to try to establish a connection. If connect () returns the rapid success or failure of a ECONNREFUSED, the following TCP stack must have received a SYN / ACK or RST, it will be the host flag is in operation. If the connection times out, the host can flag down for the out. This method is also used for IPv6 connections, as Nmap does not currently support the original IPv6 packets.

** - PA [portlist] (TCP ACK Ping) **

SYN ping and TCP ACK ping is quite similar to the just discussed. Maybe you have already guessed, the difference is to set the TCP ACK flag instead of SYN flag. ACK packet to confirm a attempt to establish a connection, but the connection has not been fully established. So remote hosts should always respond with a RST packet, because they have not issued a connection request to the machine running Nmap, if they are running then.

-PA option uses the same default port (80) SYN probe, you can also specify a target list of ports with the same format. If a non-privileged user attempts to this feature, or specifies the IPv6 destination, said before the connect () method will be used. This method is not perfect, because it is actually sent SYN packets instead of ACK packets.

The reason for providing two kinds of SYN and ACK ping probes is the opportunity through the firewall as large as possible. Many administrators configure their router or other simple firewalls to block SYN packet, unless the connection is made, those disclosed as the company's Web site server or mail server. This prevents other connections into the organization, but also allow users to access the Internet. This stateless approach takes up little resources firewall / router, which is widely supported by hardware and software filters. Linux Netfilter / iptables firewall software offers a convenient option to implement this approach --syn stateless. When there is no firewall rules state, is sent to the destination port closed SYN ping probe (-PS) are likely to be blocked. In this case, ACK probe exceptionally bright spot, because it just takes advantage of such a rule.

Another common firewall to block unintended message with stateful rules. This feature has begun to exist only in high-end firewalls, but these years like it more and more common. Linux Netfilter / iptables support this feature by --state option, which according to the connection state to classify packets. SYN probe is more likely for such a system, since the ACK packets are usually senseless are discarded identified as counterfeit. The solution to this dilemma is another that is designated by the specified -PS -PA to send SYN That in turn sends ACK.

** - PU [portlist] (UDP Ping) **

There are a host discovery option is the UDP ping, which sends an empty (unless specified --data-length UDP packet to the given port. Port format and the previous list discussed -PS and -PA options or the same. If you do not specify a port, the default is 31338. this default value can be configured by changing the dEFAULT-UDP-PROBE-pORT value nmap.h file at compile time. using such a strange default port because of the open port this scan generally unpopular.

If the target machine's port is closed, UDP probe should immediately get a response packet ICMP port unreachable. This means that the machine Nmap is running. Many other types of ICMP errors, such as host / network unreachable or TTL timeout is down or unreachable host said. No response has also been explained. If you reach an open port, most services only ignore the empty packet without making any response. This is why the default probe port is 31338 port such a highly unlikely to be used. A small number of services such as chargen will respond to an empty UDP packet, so Nmap to indicate that the machine is running.

The main advantage of this scan type is that it can pass through only filtering firewall and TCP filters. E.g. I used to have a Linksys BEFW11S4 wireless broadband router. By default, the device and external network adapter filtering all TCP ports, UDP probe but will still lead to a port unreachable message, which betrays its own.

** - PE; -PP; -PM (ICMP Ping Types) **

In addition to these unusual TCP and UDP host discovery types discussed previously, Nmap can send the world knows ping program to send the message. Nmap sends an ICMP type 8 (echo request) packet to the destination IP address, to expect a type 0 (echo response) message from the host is running. For Internet Explorer, the Unfortunately, many hosts and firewalls now block these packets, rather than respond as expected, see [RFC 1122] (http://www.rfc-editor.org/rfc/rfc1122 .txt). Therefore, only ICMP scanning for targets on the Internet is usually not enough. But for system administrators monitoring an internal network, they may be practical and effective way. Use -PE option to open the echo request function.

While echo request is the standard ICMP ping query, Nmap does not stop there. ICMP standard ([RFC 792] (http://www.rfc-editor.org/rfc/rfc792.txt)) also regulates the timestamp request, the request information request, and address mask request, they are code is 13 , 15 and 17. Although the surface of the object query is to obtain information such as the current time and the address mask, which can be easily used for host discovery. Very simple response system is the system in operation. Nmap does not currently implement information request packets, because they have not been widely supported. RFC 1122 adhere to the "hosts should not implement these messages." Timestamp and address mask queries can be sent separately by -PP and -PM options. Response time stamp (ICMP Code 14) or address mask response (code 18) indicates that the host is running. When the administrator blocked the particular echo request packets while forgetting other ICMP queries may be used for the same purpose, these two queries may be valuable.

** - PR (ARP Ping) **

One of the most common Nmap usage scenarios is to scan an Ethernet LAN. On most LANs, especially those using RFC1918 private address ranges based on the network, at a given time the vast majority of IP addresses are not in use. When the original IP Nmap try to send a message such as ICMP echo request, the operating system must be determined corresponding to the target IP address of the hardware (the ARP), the Ethernet frame so that it can be sent to the correct address. This is generally slower but also some problems, because the operating system designers generally do not believe that in a short time as an ARP request millions of times the machine is not running.

When ARP scanning, Nmap request in its ARP management optimization algorithm. When it receives a response, Nmap does not even need to worry about IP-based ping packets since it already knows the host is running. This makes ARP scan faster and more reliable than IP-based scans. So by default, if Nmap find the target host on the LAN on which it is, it will be ARP scan. Even ping specify different types (e.g. -PI or -PS), Nmap also uses ARP to any target on the same LAN. If you really do not want to ARP scan, specify --send-ip.

** - n (no DNS) **

Never tell Nmap its active IP addresses found in reverse domain name resolution. Since DNS is generally more slowly, which can make things faster.

** - R (for all target to resolve domain names) **

Nmap always tell the target IP address for reverse domain name resolution. Only when the general findings of this operation when the machine is running.

** - system-dns (domain name resolver using the system) **

By default, Nmap to resolve the domain name query to the DNS server configuration on your host by directly sending. To improve performance, many requests (typically tens) execute concurrently. If you want to use the system comes parser, specify this option (by getnameinfo () call to resolve a once IP). Unless the Nmap DNS code has bug-- If so, please contact us. Generally do not use this option because it is much slower. The system resolver is always used for IPv6 scans.

# # Basic port scan

While Nmap over the years more and more functions, it is also an efficient port scanner from the beginning, and that remains its core function. nmap <target> This simple command scans the host more than 1660 TCP ports on the <target>. . Many traditional port scanner only list all ports are open or closed, Nmap information much more granularity than they should be fine. It ports into six states: open (open), closed (closed), filtered (filtered), unfiltered (unfiltered), open | filtered (open or filtered), or closed | filtered (closed or filtered).

These are not state the nature of the port itself, but describe how Nmap look at them. For example, for a 135 / tcp port similar to the target machine, with the display from the network scan it is open, the same scan across the network as it may be displayed Filtered (filtered).

Nmap identified six port status:

** open (open) **

Application is received by the port TCP connection or UDP packets. This discovery is often the main goal of port scanning. A strong sense of security that people know each inlet port is open to attack. Attacker or penetration tester wants to find open ports. The administrator is trying to shut them down or use a firewall to protect them so as not to interfere with the legitimate user. Non-security scans may also be interested in the open ports, because they show those services available on the network.

** closed (closed) **

Closed ports for Nmap is accessible (it receives Nmap probe packets and respond), but there is no application listening on it. They can (host discovery, or ping scanning) the host is running up also helpful on the part of the operating system detects the IP address of the display. Due to the closure of the gateway is accessible, perhaps you had a moment worth re-scan it, could something so open. System administrators may consider blocking such ports with a firewall. As they will be displayed as filtered state, discussed below.

** Filtered (filtered) **

Since packet filtering to block a probe packet reaches the port, Nmap can not determine whether the port is open. Filtering firewall device may come from professional, router or software firewall rule on the host. This port allows an attacker to feel very frustrated, because they almost do not provide any information. Sometimes they respond to ICMP error message, such as Code 13 type 3 (Destination Unreachable: a communication prohibited by the administrator), but more generally simply discard the filter probe frames, makes no response. This forces Nmap several retries access in the event of network congestion due to the probe packet is discarded. This makes the scanning speed was slow.

** unfiltered (unfiltered) **

Unfiltered state means that a port is accessible, but Nmap can not determine whether it is open or closed. Only the firewall rule set for mapping ACK scan the port will be classified to this state. Other types of scanning such as a scanning window, scan the SYN, FIN scan to scan or unfiltered ports can help determine whether the port is open.

** open | filtered (open or filtered) **

When the port is open or not is determined filtered, Nmap put the port into this state. Open ports do not respond is an example. No response could also mean that a packet filter dropped the probe packet or any response it triggered. So Nmap can not determine whether the port is open or filtered. UDP, IP protocol, FIN, Null, and Xmas scans the port may fall into this category.

** closed | filtered (closed or filtered) **

This state can not be determined for Nmap port is closed or filtered. It may only appear in the IPID Idle scan.

# # Port scanning techniques

As a novice mechanic, I might toss a few hours to explore how the basic tools (hammer, tape, wrench, etc.) for the task at hand. When I fail tragically, my old car onto a real technician got there, he was always in his toolbox to roll until it brings out a perfect tool to get it then seem effortless. And the art of port scanning is similar. Experts understand the dozens of scan techniques and choose the most suitable one (or a combination) to complete a given task. On the other hand, just inexperienced users and beginners always solve every problem with the default SYN scan. Since Nmap is free, the only barrier to master port scan is knowledge. This is of course the automotive world can not be compared, where possible require great skill to determine that you need a strut spring compressor, then it is that you have to pay thousands of dollars.

Most of the scan types are only available to privileged users. This is because they transmit and receive raw packets, which requires root privileges on Unix systems. On Windows administrator account is recommended, but when WinPcap has already been loaded into the operating system, non-privileged users can also use normal Nmap. When Nmap was released in 1997, it requires root privileges was a serious limitation, since many users only shared shell accounts. Now, the world has changed, computers cheaper, more people with an Internet connection, a desktop UNIX systems (including Linux and MAC OS X) is very common. The Windows version of Nmap now have, which allows it to run on even more desktops. For all these reasons, users no longer need to Nmap with limited shared shell accounts run. This is fortunate, because the privileged options make Nmap far more powerful but also much more flexible.

While Nmap effort to produce correct results, but keep in mind that all results are based on the target machines (or firewalls in front of them) returned messages. . These hosts may be untrustworthy, they may respond to confuse or mislead Nmap's message. More generally non-RFC-compliant host in response to an incorrect manner Nmap probe. FIN, Null, and Xmas scans are particularly vulnerable to encounter this problem. These are the particular scan type of problem, so we discuss them in the individual scan type.

This section discusses the support of about a dozen Nmap scanning techniques. Usually only one time, except that UDP scan (the -sU) and may be any of a TCP scan type combination. Friendly reminder, port scan type format option is -s <C>, where <C> is a prominent character, usually the first character. One exception is deprecated FTP bounce scan (-b). By default, Nmap to perform a SYN scan, but if the user does not have permission to send raw packets (requires root privileges on UNIX) or if IPv6 target is specified, Nmap call to connect (). Scanning listed in this section, unprivileged users can only execute connect () and ftp bounce scans.

** - sS (TCP SYN scan) **

SYN scan as the default and most popular scan option, is for good reason. It performs very quickly, there is no intrusion on a fast network firewall, scanning thousands of ports per second. SYN scan is relatively quieter, less noticeable, because it is never complete TCP connection. Nor does it Fin / Null / Xmas, Maimon and Idle scans tied to a particular platform, and can cope with any compatible TCP protocol stack. It can reliably distinguish clearly open (open), closed (closed), and filtered (filtered) state

It is often referred to as semi-open scanning, because it is not fully open a TCP connection. It sends a SYN packet, as if you really want to open a connection and then wait for a response. SYN / ACK indicates that the port in the listening (open), the RST (reset) indicates no listener. Still it did not respond if the retransmission number of times, the port is marked as filtered. Receiving an ICMP unreachable error (type 3 code 1,2,3,9,10, or 13), the port is also marked as filtered.

** - sT (TCP connect () scan) **

When SYN scan can not be used, CP Connect () scan is the default TCP scan. When the user does not have permission to send the original message or when scanning IPv6 networks, as is the case. Instead of writing raw packets as most other scan types do, Nmap by creating a connect () system call operating system requirements and target port and establishing a connection, unlike other types of scanning an original packet transmitted directly. This is the browser and the Web, P2P clients, and most other network applications to establish a connection the same high-level system calls. It is a part called the Berkeley Sockets API programming interface. Nmap obtaining state information for each connection attempt using this API, you instead of reading the original response message.

When SYN scan is available, it is usually the better choice. Since Nmap () call than the original message control less, so the lower the efficiency of the former high-level connect. The open system call is fully connected to the destination ports rather than semi-open SYN scan reset. Not only does this take longer and require more packets to obtain the same information, the target machines are more likely to record the connection. IDS (Intrusion Detection System) can capture both, but most of the machines is no such alarm system. When Nmap connection, then do not send the data and close the connection, many common services on UNIX systems will stay logged in syslog, and sometimes an encrypted error message. At this point, some really poor service crash, although this rarely occurs. If the administrator logs saw a bunch of connection attempts from the same system, she should know that her system was scanned.

- ** sU (UDP scans) **

While many popular services on the Internet run over the TCP protocol, [UDP service] (http://www.rfc-editor.org/rfc/rfc768.txt) either. DNS, SNMP, and DHCP (registered ports is 53,161 / 162, and 67/68) are the three most common. Because UDP scanning is generally slower and more difficult than TCP, some security auditors ignore these ports. This is a mistake, because detectable UDP services are quite common and attackers certainly do not ignore the whole protocol. Fortunately, Nmap can help record and report UDP port.

UDP scan is activated with -sU option. It can be scanned as TCP SYN scanning (-sS) using both protocols at the same time check the binding.

UDP scan sending an empty (no data) UDP header to each target port. If the ICMP port unreachable error (type 3 code 3), the port is Closed (closed). Other ICMP unreachable error (type 3 code 1,2,9,10, or 13) indicates that the port is Filtered (filtered). Occasionally, a service will respond with a UDP packet to prove that the port is open (open). If after several retries has not responded, the port is considered open | filtered (open | filtered). This means that the port could be open, and may also contain filters are blocking traffic. Can help with a version of the scanner (-sV) to distinguish between true open port and the port is filtered.

UDP scanning huge challenge is how to make it faster. Open and filtered ports rarely respond, then let Nmap timeout detection, or prevent the probe response frame loss. Closed ports is often a bigger problem. They usually send back an ICMP port unreachable error. Unlike TCP port but closing in response to the SYN RST packet transmitted or Connect scan, many hosts default limit ICMP port unreachable message. Linux and Solaris are particularly strict on this. For example, Linux 2.4.20 kernel limits a second transmitting only a Destination Unreachable message (see net / ipv4 / icmp.c).

Nmap to detect rate limiting and slows down accordingly to avoid useless packets discarded by those target opportunities to network congestion. Unfortunately, Linux is a second type a message limit the 65,536 port scan take more than 18 hours. UDP accelerated scanning method comprising the concurrent scanning more hosts, only the first main port quick scan, scanning from behind a firewall, using --host-timeout to skip slow hosts.

** - sN; -sF; -sX (TCP Null, FIN, and Xmas scans) **

These three scan types (type --scanflags more options and even described in the next section) excavated in a [TCP RFC] (http://www.rfc-editor.org/rfc/rfc793.txt) in method to distinguish subtle open (open) and closed (closed) port. Page 65 "If [the target] port state is closed into the free .... RST causes a RST packet in response." The following discussion is not provided a SYN, RST, ACK bit or packet sent to open ports: "In theory, this should not happen if you did receive, it discards the packet is returned."

If the scanning system follows the RFC, when the port is closed, does not contain any of the SYN, RST, ACK bit or a RST packet will lead to a return, and when the port is open, there should be no response. It does not contain SYN, RST, or ACK, any combination of the other three (FIN, PSH, and URG) are OK. There are three types of Nmap scans take advantage of this:

** Null scan (-sN) **

Any flag not set (tcp flag header is 0)

** FIN scan (-sF) **

Set only TCP FIN flag.

** Xmas scan (-sX) **

Setting FIN, PSH, and URG flag, like a Christmas tree lighting on all the lights.

In addition to a probe packet flag bit different, these three scans exactly the same in behavior. If you receive a RST packet, the port is considered closed (closed), while no response means that the port is open | filtered (open or filtered). Receiving an ICMP unreachable error (type 3, code 1,2,3,9,10, or 13), the port is marked as filtered.

The key advantage scanning is that they can escape some of the stateless packet filtering firewall and router. Another advantage is that these scan types secretive than even some of the SYN scan. But do not rely on it - most modern IDS products can be found in them. A big drawback is that not all systems are strictly follow the RFC 793. Many systems regardless of the port is open or closed, have responded to RST. This causes all ports are marked as closed (closed). Such operating systems are mainly Microsoft Windows, many Cisco devices, BSDI, and IBM OS / 400. But this scan for most UNIX systems can work. Another deficiency of these scans is that they can not distinguish open (open) ports and certain filtered (filtered) ports to return to open | filtered (open or filtered).

** - sA (TCP ACK scan) **

Differs from the other scanning this scan discussed so far determined that it can not open (open) or open | filtered (open or filtered)) port. It is used to find the firewall rules to determine whether they are stateful or stateless, which ports are being filtered.

ACK scan probe packet only the ACK flag (unless you use --scanflags). When scanning unfiltered systems, open (open) and closed (closed) port will return RST packets. Nmap mark them Unfiltered (unfiltered), meaning that ACK packet can not reach, but as they are open (open) or Closed (closed) can not be determined. Specific port or send ICMP error message (type 3, code 1,2,3,9,10, or 13) does not respond to the port labeled Filtered (filtered).

** - sW (TCP Window scan) **

In addition to distinguish open ports and close the ports, when receiving unfiltered RST is not always printed using a particular system implementation details, and ACK scanning window scanning the same. It is by examining the returned RST packet domain TCP window to do this. On some systems, open ports represented by a positive number window size (even for RST packets) to close the port window size is zero. Thus, when receiving the RST, the scanning window is not always Unfiltered ports are labeled, but according to the TCP window size is 0 or a positive number, respectively, the port is marked as open or closed

This scan is dependent on a small number of systems implementation details on the Internet, so you can not always believe it. It does not support the system will usually return all ports closed. Of course, there is no open ports on a machine is also possible. If most scanned ports are closed, but some common ports (eg 22, 25, 53) are filtered, the system is very suspicious. Occasionally, the system will even display the opposite behavior. If your scan shows 1000 open ports and 3 closed or filtered ports, then those three are likely to also open ports.

** - sM (TCP Maimon scan) **

Maimon scan is named after its discoverer, Uriel Maimon's. Magazine issue # He described the technique 49 (November 1996) in Phrack. Nmap in two after the addition of this technology. The technology and Null, FIN, and Xmas scans exactly the same, except that the probe packet is FIN / ACK. According to RFC 793 (TCP), whether the port is open or closed, should respond to such a probe RST packets. However, Uriel noticed if the port is open, many BSD-based systems simply drop the probe packet.

** - scanflags (custom TCP scan) **

The real advanced Nmap users need not be bound by these type of scan ready. --scanflags option allows you to design your own scan by specifying arbitrary TCP flags. Let your creativity flow, dodge those intrusion detection systems alone this manual to add rules!

--scanflags option can be a digital tag value as 9 (PSH and FIN), but using character names easier. As long as URG, ACK, PSH, RST, SYN, and FIN any combination of the line. For example, - scanflags URGACKPSHRSTSYNFIN set all the flags, but this is not much use for scanning. Flag sequence is not important.

In addition to setting the flag need, you can also set the TCP scan type (such as -sA or -sF). That tells Nmap how to interpret basic types of response. For example, SYN scan implies that there is no response filtered port, while the FIN scanning is considered to be open | filtered. In addition to using your specified TCP flag, Nmap will scan and basically the same type of work. If you do not specify a base type, use the SYN scan.

** - sI <zombie host [: probeport]> (Idlescan) **

This advanced scan method allows for a real target blind TCP port scan (meaning no packets are sent from your real IP address of the target). In contrast, side-channel attack information generation algorithm snoop open port on the target by a known zombie host IP fragmentation on the sequence ID. IDS systems will display the scan from the zombie machine you specify (must be running and meet certain criteria). This type of scan wonderful too complicated, can not fully describe here, so I wrote an informal paper, published in the [https://nmap.org/book/idlescan.html](https://nmap. org / book / idlescan.html).

In addition to extreme hidden (because it does not send any message from the real IP address), the type of scan can establish a trust relationship between the IP-based machine. Port list from the perspective of zombie hosts. Show open ports. So you think you can try to use (via router / packet filter rules) may be trusted zombies scan target.

If you change due IPID probe a particular port on the zombie want, you can add a colon and the port number after the zombie host. Otherwise Nmap will use the default port (80).

** - sO (IP protocol scan) **

IP protocol scan allows you to determine which target IP protocol support (TCP, ICMP, IGMP, etc.). Technically, this is not a port scan, since it is traversed IP protocol numbers rather than TCP or UDP port number. But it still uses the -p option to select the protocol number to be scanned, using the normal port table format for reporting the results, and even with true port scanning the same scanning engine. And so it is very close to the port scanning, it has also been placed discussed here.

In addition itself is useful, protocol scan also showed the power of open source software. Although the basic idea is very simple, I never thought past this feature increases have not received any request to it. In the summer of 2000, Gerhard Rieger conceived the idea, wrote a great patch, is sent to the nmap-hackers mailing list. I put that patch joined the Nmap, released a new version the next day. Almost no commercial software have users enthusiastic enough to design and contribute their improvements.

Protocol scan works in a similar way and UDP scans. It is not in the UDP port field of the packet cycle, but cycles on IP protocol field 8, sends an IP packet header. Headers are usually empty, containing no data, not even contain the correct report as stated in the protocol packet header TCP, UDP, and ICMP are three exceptions. They will use three normal protocol headers, because otherwise some systems refuse to send, and Nmap has functions to create them. Note that the scan protocol is not ICMP port unreachable message, but ICMP protocol unreachable messages. If no response is received Nmap, Nmap put that agreement any protocol from the target host is marked as open. ICMP protocol unreachable error (type 3, code 2) causes the protocol is marked as closed. Other ICMP protocol unreachable (Type 3, code 1,3,9,10, or 13) results in marked Filtered protocol (ICMP proved though they are simultaneously open). If the retry after no response is received, the protocol is marked as open | filtered

** - b <ftp relay host> (FTP bounce scan) **

An interesting feature of the FTP protocol ([RFC 959] (http://www.rfc-editor.org/rfc/rfc959.txt)) is to support the so-called proxy ftp connections. It allows users to connect to an FTP server, and requires the file to a third party server. This feature is being abused on many levels, so many servers have stopped supporting it. One of which is leading to an FTP server to port scan other hosts. As long as the FTP server in turn sends a request to the file of interest port on the destination host. An error message describing the port is open or closed. This is a good way to bypass firewalls because the FTP server is often placed in the position of the host can access the Web more than the other internal hosts. Nmap supports ftp bounce with the -b option to scan. Parameter format <username>: <password> @ <server>: <port>. <Server> is the name of a vulnerable FTP server or IP address. You may be able to omit <username>: <password>, if open anonymous user (user: anonymous password: -wwwuser @) on the server. Port number (as well as before the colon) may be omitted, if <server> default FTP port (21).

When Nmap1997年发布时, this weakness has been widely used, but now most have been a fix. Vulnerable servers still exist, so if others have failed, it is worth a try. If your goal is to bypass the firewall, scanning for open ports on the target network 21 (or even any ftp services if you scan all ports with the version detection), then try to bounce each scan. Nmap will tell you that the host vulnerable or not. If you just try to play with Nmap, you do not need (in fact, should not) limit yourself. When you randomly find vulnerable FTP server on the Internet, consider the system administrator so that you do not like the abuse of their servers.

Port Description and scanning order # #

In addition to all the scanning method discussed above, Nmap the option to indicate those ports are scanned and the scanning or random order. By default, Nmap with the specified protocol and higher port nmap-services file listed 1-1024 port scan.

** - p <port ranges> (only scan the specified port) **

This option specifies the port that you want to scan, override the default values. Single port and port range (e.g., 1-1023) represented by the hyphen can. Start and / or end of the range of values ​​may be omitted, and 1, respectively, resulting in the use Nmap 65535. So you can specify -p- to scan ports from 1 to 65535. If you specified, you can also scan ports 0. For IP protocol scanning (-sO), this option specifies the protocol number (0-255) that you want to scan.

When scanning both TCP port and UDP port scan, you can add the port number before the T: or U: specify the protocol. You qualifier agreement remains in effect until another is specified. For example, the parameter -p U: 53,111,137, T: 21-25,80,139,8080 scan UDP ports 53,111, and 137, while the TCP port scan lists. Note that to scan both UDP and scanning TCP, you must specify, as well as at least one type of scanning TCP (such as -sS, -sF, or -sT) -sU. If no protocol qualifier is given, the port number will be added to the list of all the agreements.

** - F (Fast (limited port) scan) **

In the nmap nmap-services file (for -sO, a protocol file) that you want to scan the specified port. This ratio is much faster to scan all 65,535 ports. Because this list contains so many TCP ports (more than 1,200), which is the default TCP scan and scan (about 1600 ports) speed difference is not great. If you specify your own tiny nmap-services file with --datadir option, the difference will be very alarming.

** - r (scan ports Do random order) **

By default, the port scan Nmap random order (except for efficiency considerations, conventional forward port). This randomization is usually welcome, but you can specify -r for sequential port scanning.

# # Service and version detection

Nmap to point to a remote machine, it might tell you that ports 25 / tcp, 80 / tcp, and 53 / udp are open. Containing about 2,200 well-known services nmap-services database, Nmap can report that the port may correspond to a mail server (SMTP), web server (HTTP), and domain name server (DNS). This query is usually correct - in fact, the vast majority of mail server daemon listening on TCP port 25. However, you should not bet on it! It is entirely possible to run services on strange ports.

Even if Nmap is right, assuming that the service is indeed running SMTP, HTTP and DNS, it is not particularly much information. When your company or customers for safety assessments (or even simple network detailed list), you really want to know what the mail server and domain, and the version is running. There is a precise understanding of the server version of what is a huge loophole help. Version detection helps you obtain this information.

After the discovery and TCP / UDP port or in some other type of scanning methods, version detection will ask these ports, in the end determine what services are running. nmap-service-probes database contains query expressions to match the different services of the probe packet parsing and recognition of a response. Nmap tries to determine the service protocol (such as ftp, ssh, telnet, http), the application name (eg ISC Bind, Apache httpd, Solaris telnetd), the version number, hostname, device type (such as a printer, router), operating system family ( such as Windows, Linux) as well as other details, such as whether you can connect X server, SSH protocol version, or the KaZaA user name). Of course, not all services provide all of this information. If Nmap was compiled with support for OpenSSL, it will connect to the SSL server, figure out what service encryption layer behind the listener. When they find RPC services, Nmap RPC grinder (-sR) will automatically be used to determine the RPC program and its version number. If you still can not be determined after a UDP port scan the port is open or filtered, then the port status is marked as open | filtered. Version detection will try to trigger a response from these ports (just as it has open ports to do the same), if successful, put the status to open. open | filtered TCP port treated in the same way. Note that Nmap -A option open version detection in other cases. An article on the principle version detection, use and customize the [http://www.insecure.org/nmap/vscan/](http://www.insecure.org/nmap/vscan/) article.

When Nmap receives a response from a service but can not find a match in the database, it will print a special fingerprint and a URL for you to submit, if you really know what services run on port. Please take two minutes to submit your findings, so that everyone benefited. Due to these submissions, Nmap has more than 350 kinds of protocols such as smtp, ftp, http, etc. of about 3,000 pieces of pattern matching.

Open to detect and control version with the following options:

** - sV (version detection) **

Open version detection. You can also open OS detection and version detection simultaneously with -A.

** - allports (do not rule out any port version detection) **

By default, Nmap version detection skips the 9100 TCP port, because some printers simply print any data sent to the port, this time leading to dozens of pages of HTTP get requests, binary SSL session requests, etc. are printed. This behavior can be changed Exclude indicator nmap-service-probes by modifying or deleting, you can ignore any Exclude designator --allports scan all ports

** - version-intensity <intensity> (Set version scan intensity) **

When the scanned version (-sV), nmap probe sends a series of packets, each packet is assigned a value between 1-9. Is assigned a lower value of the probe packet on a wide range of common services effectively, and to be given a higher value of the message is generally useless. Which illustrates the intensity level of the probe packets should be used. The higher the value, the more services are likely to be correctly identified. However, high intensity scans take more time. Intensity value must be between 0 and 9. The default is 7. When registered to the target port detection packet via nmap-service-probes ports indicator, no matter what the intensity level of the probe packets will be tried. This ensures that the DNS probe will always attempt to open any port 53, SSL port 443 will attempt to detect, and so on.

** - version-light (lightweight open mode) **

This is a convenient 2 --version-intensity aliases. Lightweight mode makes version scanning much faster, but the possibility of its recognition service is also slightly smaller.

** - version-all (try each probe) **

--version-intensity 9 aliases, try to ensure that each probe packet for each port.

** - version-trace (track version scan activity) **

This causes Nmap to print out detailed debugging information on the progress of the scan. It is a subset of the information that you use --packet-trace obtained.

** - sR (RPC scan) **

This approach and many port scanning methods in combination. It was found that all open TCP / UDP port execution SunRPC program NULL commands in an attempt to determine whether they are RPC ports, and if so, what program and version number. So you can efficiently obtain and ** rpcinfo -p ** same information (or a protected TCP wrappers) even if the port mapping target behind a firewall. Decoys are not currently work with RPC scan. This is a version of the scanner (-sV) part opens automatically. As the probe, including its version and much more comprehensive, -sR rarely needed.

# # OS Detection

Nmap is one of the most famous features for remote OS detection using TCP / IP protocol stack fingerprinting. Nmap sends a series of TCP and UDP packets to the remote host, in response to each bit of the check. After making a dozen tests such as TCP ISN sampling, TCP options support and ordering, IPID sampling, and the initial window size check, Nmap the results and the database nmap-os-fingerprints of more than 1500 known OS fingerprints are compared, If there is a match, then print out the details of the operating system. Each fingerprint comprises a text description of the OS on a free-form, and a classification information, which provides vendor name (such as the Sun), the following operating systems (e.g., the Solaris), OS version (e.g., 10), and device type (Universal equipment, router, switch, game console, etc.).

If Nmap can not guess the operating system, and some well known conditions (such as at least found an open port and one closed port), Nmap will provide a URL, if you ascertain the operating system is running, you can submit to fingerprint that URL. This allows you to expand the knowledge base Nmap's operating system, so that every Nmap users will benefit.

Operating system can detect a number of other tests that can use the information collected during processing. For example, run-time detection, using the TCP timestamp option (RFC 1323) to estimate the host last restart time, which applies only to provide a host of such information. The other is the TCP sequence number prediction classification, used to test the TCP connection may be difficult to establish a forged for the remote host. This use of credible relationships (rlogin, firewall filters, etc.) based on the source IP address or implicit source address of attack is very important. Now this type of spoofing attacks are rare, but some hosts still loopholes in this regard. The actual difficulty value based on statistical sampling, so there may be some fluctuations. Britain's usually better classification, such as "worthy challenge" or "trivial joke". Only in a conventional manner in verbose mode output (-v), if use -O, IPID also reported sequence generation number. Many host sequence number is "increase" category, that is, increase the value of ID field in the IP header of each packet transmission, this is a loophole for some advanced information gathering and spoofing attacks it.

[Https://nmap.org/book/osdetect.html](https://nmap.org/book/osdetect.html) document describes the multilingual version detection ways to use and customize.

The following options to enable and control the operating system detects:

** - O (Enable OS detection) **

You can also use -A to enable both OS detection and version detection.

** - osscan-limit (operating system for the detection of specified targets) **

If you find a open and close the TCP port, the operating system will be more effective detection. With this option, only the host Nmap satisfies this condition is detected the operating system, this can save time, especially when using -P0 scanning multiple hosts. This option only works when using an operating system or -A -O detected.

** - osscan-guess; --fuzzy (presumably OS detection results) **

When Nmap can not determine the operating system detected, it will provide the closest possible match, Nmap default for such matches, use any of these options make Nmap guess more effective.

Time and performance # #

Nmap development the highest priority is performance. Requires 1/5 second local network to a host default scan (nmap <hostname>). But only a blink of time, you need to scan a host thousands or even hundreds of thousands. In addition, certain scan options will significantly increase the scan time, such as UDP scanning and version detection. Similarly, the firewall configuration and special speed limit will increase response time. Nmap uses a parallel algorithm and many advanced algorithms to accelerate scanning, Nmap users on how to work the final control. Advanced users can fine-tune, Nmap commands to obtain information they care about while meeting the required time.

Improve scan time technologies: ignore non-critical testing, upgrade to the latest version of Nmap (performance enhancements continue to improve). Parameter optimization time will bring substantial changes, these parameters are as follows.

** - min-hostgroup <milliseconds>; --max-hostgroup <milliseconds> (resize parallel scanning group) **

Nmap has the ability to scan multiple parallel host port or version, Nmap plurality destination IP address space into groups, and then scanned a group at the same time. Typically, a large group more effective. The disadvantage is that only after the end of the scan the entire group will provide a host of scan results. If the group size is defined as 50, only the current scan is finished after 50 hosts to get the (supplementary information except verbose mode) report.

Under default, Nmap take a compromise approach. Small group at the start of the scan, the minimum is 5, it is easy to produce results quickly; group then grow in size, up to 1024. The exact size depends on the given options. In order to ensure efficiency, TCP or UDP scanning for a small port, Nmap large groups.

--max-hostgroup option is used to illustrate the use of the largest group, Nmap will not exceed this size. Option Description --min-hostgroup smallest group, Nmap greater than this value will remain set. If there is not enough target host on the specified interface to meet the specified minimum value, Nmap may use a value smaller than the specified group. These two parameters, although rarely used, but are used to keep the size of groups within a specified range.

The main purpose of these options is to demonstrate a minimum group size so that the entire scan more quickly. Scan 256 is typically selected to class C network segment. For more scanning port number, beyond which no meaning. For the small number of ports to scan, 2048 group size or larger is helpful.

** - min-parallelism <milliseconds>; --max-parallelism <milliseconds> (adjusting parallelism of the probe packets) **

These options control packet used to detect the number of packets the host group, the host can be used for port scanning and discovery. By default, Nmap calculates a desired degree of parallelism based on network performance, this value is frequently changed. If the packet is discarded, Nmap slow, reducing the number of probe packets. With the improvement of network performance, the ideal number of text message detection increases slowly. These options determine the size range of this variable. By default, when the network is not reliable, the ideal value may be a degree of parallelism, under good conditions, may grow to several hundred.

The most common application is --min-parallelism is greater than 1, in order to speed up the scanning poor performance or network host. This option has the risk, if the impact is too high accuracy, but also reduce the ability of Nmap based on network conditions to dynamically control the degree of parallelism. The value of 10 is appropriate, the adjustment value is often used as a last resort.

--max-parallelism option is usually set to 1, in order to prevent Nmap probe packets to send multiple hosts at the same time, and select --scan-delay while using very useful, though this option to use their own has been very good.

** - min-rtt-timeout <milliseconds>, ​​--max-rtt-timeout <milliseconds>, ​​--initial-rtt-timeout <milliseconds> (adjusted ICMPv6) **

Nmap uses a running timeout value to determine the wait for a probe packet response time, then give up or re-send probe packets. Nmap timeout value is calculated based on the response time of a probe packet, if the network delay and more significant uncertainty, several seconds may increase the time-out value. Conservative initial value (high), and when no response Nmap scanning host, a conservative value for a period of time.

These options in milliseconds, using small --max-rtt-timeout value, so --initial-rtt-timeout value larger than the default value may significantly reduce the scan time, especially not ping scan pass (-P0) and strict filtering network. If the value is too small, so that so many ICMPv6 resend, and it is probable response message being sent, which makes the whole scan time increases.

If all of the hosts in the local network, for --max-rtt-timeout value, the 100 ms is appropriate. If the route exists, the first to use ICMP ping tool ping a host, or use other tools such as message hpings, can better penetrate the firewall. See approximately 10 packets maximum round-trip time, then --initial-rtt-timeout is set to twice this time, - max-rtt-timeout can be set to three times the value of the time or 4 times. In general, no matter how many ping time is the biggest rtt value must not be less than 100ms, can not exceed 1000ms.

--min-rtt-timeout This option is rarely used, when the network is unreliable, the default value Nmap also appears to be too strong, then this option to work. When the network does not look reliable, Nmap only the timeout down to the minimum, this situation is not normal, you need a list of bug reports to the nmap-dev mailing.

** - host-timeout <milliseconds> (abandoned low target host) **

Due to poor performance or unreliable networking hardware or software, bandwidth limitations, strict firewall and other reasons, some hosts take a long time to scan. These very small number of host scans tend to occupy most of the scan time. Therefore, the best way is to reduce the time consumption and ignore these hosts, using --host-timeout option to illustrate the time (in milliseconds) to wait. 1800000 is generally used to ensure that Nmap does not use more than half an hour on a single host. Note that, Nmap During this half hour while the other hosts can be scanned, and therefore not entirely give up scanning. Timeout hosts are ignored, so there is no, or a version of the operating system detects the detection result of the output port table for the host.

** - scan-delay <milliseconds>; --max-scan-delay <milliseconds> (probe packets adjustment interval) **

This option for controlling Nmap probe packet transmission waiting time (in milliseconds) for a host computer, this option is very effective in the case of bandwidth control. Solaris host in response to the scanning probe packet UDP packets, ICMP only send a second message, a lot number of the probe packet is sent Nmap thus wasted. --scan-delay is set to 1000, so that low-speed operation Nmap. Nmap attempts to detect bandwidth control and adjust the scan delay accordingly, but does not affect how fast the best work explicitly stated.

Another use is to hide --scan-delay closing intrusion detection and prevention system threshold (IDS / IPS) based.

** - T <Paranoid | Sneaky | Polite | Normal | Aggressive | Insane> (set time template) **

Above optimization time control options are very powerful and very effective, but some users may be confused. In addition, often choose appropriate parameters to optimize the required time exceeds the scan time. Therefore, Nmap provides some simple methods, using six time template, use the -T option and digital (0--5) or name. Template names are paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4) and insane (5). The first two modes for IDS evasion, Polite mode scanning speed is reduced using less bandwidth resource and the destination host. The default mode is Normal, therefore -T3 actually not done any optimization. Aggressive mode is assumed that a user having a suitable and reliable network to accelerate scanning. Insane mode assumes that the user has a particularly fast network or are willing to sacrifice to gain speed and accuracy.

The user can select different template according to their needs by Nmap is responsible for selecting the actual time value. Templates can also fine-tune for the optimal control of other options speed. For example, -T4 prohibited for dynamic TCP port scan delay exceeds 10ms, -T5 value corresponding to 5ms. Templates can be adjusted and optimized control options used in combination, but must first specify template, template or standard value will override the value specified by the user. Recommended when scanning reliable network -T4, even when they have to increase the control options to optimize use (the beginning of the command line), so as to benefit from those extra minor optimizations.

If there is sufficient bandwidth for or Ethernet connection, it is recommended to use -T4 option. Some users prefer -T5 option, but this is too strong. Sometimes users consider to avoid the collapse of the host or want more polite will use -T2 option. They do not realize how -T Polite option is slower than scanning this mode the default mode actually spend 10 times longer. The default time options (-T3) Few host crashes and bandwidth problems, more suitable for cautious users. No version detection adjustment than the time more effectively address these issues.

Although -T0 and -T1 option may help avoid IDS alerts, but during thousands of host or port scanning, will significantly increase the time. For scanning such a long period of time rather exact set value, without going -T0 and -T1-dependent packaging options.

The main effects of T0 option for continuous scanning at a time can only scan one port, each probe packet sending interval of 5 minutes. T1 and T2 options quite similar, probe packet interval is 15 seconds and 0.4 seconds, respectively. T3 is Nmap's default option, includes parallel scanning. T4 options --max-rtt-timeout 1250 --initial-rtt-timeout 500 is equivalent to the maximum scan delay of TCP 10ms. T5 is equivalent to --max-rtt-timeout 300 --min-rtt-timeout 50 --initial-rtt-timeout 250 --host-timeout 900000, the maximum TCP scan delay of 5ms.

# Firewall / IDS and avoid deception #

Many Internet pioneers envisioned a global open network, using a global IP address space that has virtual connections between any two nodes. This makes the hosts can serve as a true peer, service delivery and access to information among each other. People can access at work all the family system, adjust the air conditioning temperature, open the door ahead of the arrival of guests. Subsequently, these global connections envisaged by the address space shortages and security concerns limit. In the early 1990s, various organizations began deploying firewalls to achieve the purpose of reducing connection, a large network through a proxy, NAT and packet filters and unfiltered Internet isolation. Unrestricted flow of information is replaced by a tightly controlled trusted communication channel stream.

Network firewall-like isolation of the network makes the search more difficult, random search is no longer simple. However, Nmap offers many features for understanding these complex networks, and test these filters are working properly. In addition, Nmap provides a means to bypass certain weak preventive mechanisms. One test network security status is the most effective way to try to coax network, we will think of myself as an attacker, using technology provided in this section to attack their own networks. Such as using FTP bounce scan, Idle scan, fragmentation attack, or try to penetrate their own agents.

In addition to limiting, behavior of the network, the use of intrusion detection systems (IDS) the company is also increasing. Since Nmap scan commonly used in the attack early, so all the mainstream IDS contains rules to detect Nmap scans. Now, these products are transformed into intrusion prevention systems (IPS), you can take the initiative to stop the suspected malicious behavior. Unfortunately, network administrators and IDS vendors by analyzing packets to detect malicious behavior is a hard work, attackers have the patience and technology, with the help of certain Nmap options, often can not be detected by IDS. Meanwhile, administrators must cope with a large number of false positive results, abnormal behavior was wrongly be altered or blocked.

Sometimes, it is suggested that Nmap should not offer features to deceive or hide closed firewall rules of IDS, these functions can be abused attacker, but the administrator be able to use these features to enhance security. In fact, the method of attack can still be exploited by attackers, they may find other tools or Nmap patch. At the same time, administrators find work attacker more difficult, compared to take measures to prevent tool to perform FTP Bounce attack, the deployment of advanced, patched FTP servers is more effective.

Nmap not provide detection and destruction firewall and IDS system magic bullet (or Nmap option), which uses the technology and experience, which is beyond the scope of this reference manual, the following describes the options and related work done.

** - f (segmented packets); --mtu (specified MTU) **

Small IP packet-segmentation scanning claim -f option (for very ping sweep). The idea is that the TCP header segment in several packets, so the packet filters, and other detection more difficult IDS tools. This option must be used with care, some systems have problems dealing with these packets, such as the old network sniffer Sniffit segmentation error occurs immediately upon receipt of the first segment. This option is used once, Nmap packet after the IP header is divided into 8 bytes or less. Thus, a 20-byte TCP header is divided into three packages, two packets each of which has eight bytes of the TCP header, the other package has a remaining 4 bytes of the TCP header. Of course, each packet has an IP header. -f can be used again using the 16-byte segments (reducing the number of segments). Can customize the size of the offset is not required when using the -f option is used --mtu, the offset must be a multiple of 8. Queuing the packet filters and firewalls all IP fragments, such as CONFIG-IP-ALWAYS-DEFRAG Linux kernel configuration items, fragment packet is not used directly. Some networks can not afford the performance hit caused by such, this configuration will be prohibited. There are other reasons prohibited fragmented packet enters the network via different routes. Some segments of the source system message sent by the kernel, the iptables connection tracking module for Linux is an example. When a similar Ethereal sniffer scan must ensure that the transmitted packet to be graded. If the host operating system will have problems, try using --send-eth option to avoid direct IP layer and send raw Ethernet frames.

** - D <decoy1 [, decoy2] [, ME], ...> (hidden using decoy scan) **

For bait scan function, it is necessary to consider the remote host is bait in scanning the target network. IDS might report 5-10 port scan a certain IP, but does not know which IP scanning and which are not in the bait. However, this approach can follow the route, as well as other active mechanism in response to the dropped solution. This is a commonly used to hide its own IP address effective technology.

Use commas to separate each decoy host, it can also be used as bait your real IP, then use the ME option instructions. If you use the ME option in the 6th position or further back, some common port scan detectors (such as Solar Designer's excellent scanlogd) will not report the real IP. If you do not use ME option, Nmap the real IP in a random location

Note that, as the host bait must be in working condition, otherwise it will lead to SYN flooding attack the target host. If there is only one host at work in the network, it is easy to determine which host scanning. IP addresses can also be used instead of a host name (was entrapped network name can not be found in the server log).

Bait available (ICMP, SYN, ACK, etc.) or a true phase in the initial stage of port scans ping sweep. Bait can also be used for remote operating system detection (-O). When version detection or TCP connect scan is performed, the bait is invalid.

Excessive use of bait no value, but lead to slow down and scan results are not accurate. In addition, some ISP will filter spoofed packets, but many do not have any restrictions on the spoof IP packets.

** - S <IP_Address> (source address spoofing) **

In some cases, Nmap may not be able to determine your source address (if so, Nmap will give prompt). At this time, -S option and IP address of the desired interface description transmitted packet.

Another use of this flag is the use of scanning so that the target is considered another address during the scan. Imagine a competitor in a continuously scans a company! -e option is often used in this case, it may also be employed -P0 option.

** - e <interface> (specified interfaces) **

Nmap tell which interface to send and receive packets, Nmap can automatically detect, if not detected will give tips.

** - source-port <portnumber>; -g <portnumber> (source port spoofing) **

It depends only on the source port number you trust the data stream is a common configuration errors, this problem is very easy to understand. For example an administrator to deploy a new firewall, but it attracted a lot of user dissatisfaction because their applications stopped working. It may be due to external UDP DNS server response can not enter the network, which led to the collapse of the DNS. Another common example is the FTP, FTP transfers at the remote server and attempts to establish a connection with the internal data to transmit.

There are solutions to these security problems, usually application-level proxy or firewall protocol analysis module. But there are some unsafe programs. Noting DNS response from the port 53, FTP connection from port 20, many administrators would fall into a trap, which allows data from the port into the network. They believe in these ports will not be worth noting that attacks and exploits. In addition, administrators may think this is a short-term measure until they take the safer approach. But they ignore the security upgrade.

Excessive workload of network administrators is not just fall into this trap, there will be a lot of this type of product itself can be very dangerous, even Microsoft's products. Windows 2000 and Windows XP IPsec filter included also included a number of implicit rules that allow all TCP and UDP traffic from port 88 (Kerberos) is. Another common example is Zone Alarm personal firewall to 2.1.25 version still allows the source port 53 (DNS) or 67 (DHCP) UDP packet to enter.

Nmap provides option -g and --source-port (they are equivalent), utilizing the above-mentioned weaknesses. Only need to provide a port number, Nmap can send data from these ports. For specific operating system to work, Nmap must use different port number. DNS requests are ignored --source-port option, because Nmap relies on system libraries to handle. Most TCP scans, including SYN scan, can fully support these options, UDP scanning the same.

** - data-length <number> (additional random data packet transmission) **

Normally, Nmap minimum transmission packets containing only a header. Thus typically 40 byte TCP packet, ICMP ECHO request only 28 bytes. This option tells Nmap additional specified number of random bytes in the message sent. OS detection (-O) packets are not affected, but most ping and port scanning packages affected, which makes processing slower, but less impact on the scan.

** - ttl <value> (Set IP time-to-live field) **

Setting IPv4 packet time-to-live field to the specified value.

** - randomize-hosts (random permutation of the sequence of the target host) **

Tell Nmap randomly arranged for each group of hosts before scanning host up to 8096 hosts. This will make scanning for different network monitoring systems become less obvious, especially when a more effective option with a smaller time value. If the need for a larger group of randomly arranged, it is necessary to increase the value nmap.h file PING-GROUP-SZ and recompile. Another method is to use the scan list (-sL -n -oN <filename>), generating a list of destination IP using Perl script randomized, then supplied to -iL Nmap.

** - spoof-mac <mac address, prefix, or vendor name> (MAC address spoofing) **

Nmap requirements specified MAC address when sending the original Ethernet frame, this option implies --send-eth option to ensure that Nmap actually sends an Ethernet packet. There are several MAC address format. If we simply use the string "0", Nmap select a completely random MAC address. If a given product is a hexadecimal character even number (using: partition), Nmap will use this MAC address. If the number is less than hexadecimal 12, Nmap randomly fill the remaining six bytes. If it is not 0 or a hexadecimal character string parameter, the name of the manufacturer looks Nmap (case sensitive) by nmap-mac-prefixes, if a match is found, Nmap uses vendor OUI (3 bytes prefix), then randomly fill the remaining the three bytes. Right --spoof-mac parameters, Apple, 0,01: 02: 03: 04: 05: 06, deadbeefcafe, 0020F2 and Cisco.

# # Output

Any security tool only if the output is valuable, if not expressed through organized and easy to understand, complex testing and algorithm almost does not make sense. Nmap provides several ways for users and other software, in fact, not a way to make everyone satisfied. So Nmap offers several formats, including convenient and direct view of the interaction and facilitate software processing XML format.

In addition to providing external output formats, Nmap also offers options to control the output of the details and debugging information. Content may be transmitted to the output standard output or file name, or overwrite may be added. Output files can also be used to continue the interrupted scan.

Nmap 5 different output formats. The default mode is the interactive output, is sent to the standard output (stdout). Interactive mode is similar to normal output, but show less runtime information and alarm information, because information is completely finished after the scan for analysis, rather than interactive.

XML output is the most important type of output, may be converted to HTML, is very convenient for program processing, such as a graphical user interface or Nmap into the database.

The other two types of output is relatively simple, grepable output format, the target host the most information in a row; sCRiPt KiDDi3 0utPUt format used to consider their own user | <-r4d.

The interactive output is the default mode, there is no corresponding command line options, the other four format options use the same syntax, using a parameter, the name of the file to store the results. A variety of formats can be used simultaneously, but the format can only be used once. For example, the standard output for viewing at the same time, you can save the results to an XML file for program analysis, then you can use the option -oX myscan.xml -oN myscan.nmap. To facilitate simplification of description, this chapter use of the simple file name like myscan.xml recommended file name is more descriptive. Select the file name and personal preferences related to the proposed increase in scan date and one or two words to describe, and placed in a directory.

While the output to a file, Nmap will send the results to standard output. For example, the command nmap -oX myscan.xml target to output XML myscan.xml, and print the results on the same interactive stdout, but this time -oX option is not employed. You can use a hyphen as the option to change, which makes Nmap ban interactive output, but the results are printed to the specified standard output stream. Thus, the command nmap -oX - target only XML output to standard output stdout. Serious error still is output to the standard error stream to stderr.

Nmap and other parameters are different spaces (such as -oX) log file options and the filename or hyphen is required. If the tag is omitted, e.g. -oG- or -oXscan.xml, Nmap backward compatibility characteristics of the standard format to create output file, and the corresponding file name G- Xscan.xml.

Nmap also provides the option to add or override control output files, and scan the details of these options follows.

Nmap output formats:

** - oN <filespec> (stdout) **

The standard requires written directly to the output file specified. As described above, this format is slightly different interactive output.

** - oX <filespec> (XML output) **

XML output is written requirements specified file directly. Nmap includes a document type definition (DTD), an XML parser so effectively XML output. This is mainly to program applications, but can also help human interpretation Nmap XML output. DTD defines valid format elements, attributes and values ​​can include use. The latest version is available at [http://www.insecure.org/nmap/data/nmap.dtd](http://www.insecure.org/nmap/data/nmap.dtd).

XML provides a stable output format for parsing software, the main computer languages ​​provide a free XML parser, such as C / C ++, Perl, Python and Java. There are a number of bundles for those languages ​​and codes for processing the output of a particular execution program Nmap. For example, the perl CPAN [Nmap :: Scanner] (http://sourceforge.net/projects/nmap-scanner/) and [Nmap :: Parser] (http://www.nmapparser.com/). Almost all major applications have interfaces with Nmap, XML is the preferred format.

XML output references an XSL stylesheet for formatting output, similar to HTML. The most convenient method is to load the XML output to a Web browser, such as Firefox or IE. Since the absolute path nmap.xsl file, so usually only Nmap is running on the machine work (or a similarly configured machine). Like any Web-enabled machines HTML file, - XML ​​stylesheet file option can be used to establish portable.

** - oS <filespec> (ScRipT KIdd | 3 oUTpuT) **

Script kiddies output similar to the interactive tool output, which is a post-processing, suitable for 'l33t HaXXorZ, because the original all uppercase Nmap output. This option and script kiddies opened a joke, seemed to be in order to "help them."

** - oG <filespec> (Grep output) **

Finally, in this way, because it is not recommended. XML output format is very powerful, easy to experienced users. XML is a standard, consists of a number parser and Grep more simplified input session. XML is extensible to support new Nmap features released. The purpose of using Grep output is to ignore these features, because there is not enough space.

However, surface, Grep output is still often used. It is a simple format, one per line host, and easy to find by decomposition and Perl UNIX utilities (such as grep, awk, cut, sed, diff). Often used for disposable test type on the command line. Find host ssh port open or run Sloaris, just a simple grep host instructions and print the desired domain channel through awk or cut command.

Grep output may contain comments (starting from each line number #). Each row consists of six domains labeled, separated by tabs and colon. These fields have a host, port, protocol, ignoring the state, operating system, serial number, IPID and state.

The most important of these fields is the Ports, which provides details of the interest of the port, the port entries separated by commas. Each port entry represents a port of interest, each sub-domains separated by /. These sub-domains are: port number, status, protocol, owners, service, SunRPCinfo and version information.

For XML output, this manual can not list all of the format, more detailed information about Nmap Grep output can be found at [http://www.unspecific.com/nmap-oG-output](http://www.unspecific.com/ nmap-oG-output).

** - oA <basename> (Output to all formats) **

For convenience, the use of -oA <basename> option scan results in a standard format, XML format and disposable Grep output format. They are stored in <basename> .nmap, <basename> .xml and <basename> .gnmap file. You can also specify a directory name before the file name, as in UNIX, use ~ / nmaplogs / foocorp /, in the Window, use the c: \ hacking \ sco on Windows.

Details and debugging options

** - v (increase output of detail) **

By increasing the detail level, Nmap more information may be output to the scanning process. Output ports found open, if Nmap scan think needs more time will show the end time estimation. This option is used twice, will provide more detailed information. The option to use more than twice does not work.

Most of the changes only affect interactive output, there are some effects of standard output and script kiddies. Other types of output processing by a machine, the default case Nmap provides detailed information, without manual intervention. However, there will be some changes in other modes, some details may be omitted to reduce the output size. For example, comment lines Grep output ports of all scan lists, but because the information is too long, it can only output mode in detail.

** - d [level] (or set the debug level increase) **

When verbose mode does not provide sufficient data for a user, using a debugger can get more information. When using the detail option (-v), to enable command-line parameter (-d), multiple use can increase the debug level. Parameters can also be used to set the debug level back -d. For example, -d9 set level 9. This is the highest level, it will generate thousands of lines of output, unless only a few ports and targets simple scan.

If Nmap because Bug and hang or have questions about the work and the principle of Nmap, debugging output is very effective. Developers mainly use this option, debug lines do not have the self-explanatory features. For example, Timeoutvals: srtt: -1 rttvar: -1 to: 1000000 delta 14987 ==> srtt: 14987 rttvar: 14987 to: 100000. If you do not understand a certain line output can be ignored, or view the source code to help developers list (nmap-dev). Some output lines will be self-explanatory features, but with increasing levels of debugging, will become increasingly vague.

** - packet-trace (trace packets sent and received) **

A summary of each packet requires Nmap print sent and received, typically used for debugging, help new users to better understand the true work of Nmap. To avoid excessive output lines, you can limit the number of the port scan, such as -p20-30. If only for version detection, use --version-trace.

** - iflist (include interfaces and routing) **

Nmap detected output interface list and routing system, the routing problem for debugging or failure device description (e.g., Ethernet Nmap treated as the PPP connection).

Other output options:

** - append-output (the output file is added) **

When used as an output file format, such as -oX or -ON, the default file is overwritten. If you want to keep the existing contents of the file, add the results after the existing file, use --append-output option. All specified output files are added. But for XML (-oX) scan output file is invalid, could not be resolved properly, you need to manually modify.

** - resume <filename> (continue to interrupt scanning) **

Some extensions Nmap runs take a very long time - in days, this type of scan often does not end. Some restrictions may prohibit Nmap runs during work hours, resulting in network outages, restart the host running Nmap planned or unplanned, the Nmap own or interruption. The administrator running Nmap could cancel the run for other reasons, you can press ctrl-C. Start a scan from the beginning may seem unpleasant, fortunately, if the standard scanning (-oN) or Grep scan (-oG) logs are retained, the user can ask Nmap resume scanning termination, simply use the options and --resume Description standard / Grep scan output file, do not allow the use of other parameters, Nmap parses the output file and the original output format. The use nmap --resume <logfilename>. Nmap new earth will result added to the file, this approach does not support the XML output format because the two runs to merge the results of an XML document more difficult.

** - stylesheet <path or URL> (XSL stylesheet set, convert the XML output) **

Nmap mention from the XSL stylesheet nmap.xsl, for viewing or convert XML output to HTML. XML output includes an xml-stylesheet, directly to nmap.xml file, which is installed by the Nmap (or in the Windows current working directory). When you open Nmap XML output in a Web browser, you will look nmap.xsl file in the file system, and use it to output. If you want to use a different style sheet, it --stylesheet as a parameter, and must specify the full path segment or URL, common invocation is --stylesheet http://www.insecure.org/nmap/data/nmap. xsl. This tells the browser to load the latest in a style sheet from Insecire.Org. This makes Nmap not installed (and nmap.xsl) machine can easily see the results. Therefore, URL and more convenient to use, nmap.xsl local file system used by default.

** - no-stylesheet (ignore the XML declaration XSL style sheet) **

Use this option to disable the Nmap XML output associated with any XSL stylesheet. xml-stylesheet instructions are ignored.

Other options # #

This section describes some important (and unimportant) the options that do not fit anywhere else.

** - 6 (IPv6 enabled scanning) **

Since 2002, Nmap provides support for some of the main features of IPv6. ping scanning (TCP-only), connect scanning, and version detection all support IPv6. In addition to increasing -6 option, the same as other command syntax. Of course, it is necessary to replace the host name using an IPv6 address, such as 3ffe: 7501: 4819: 2000: 210: f3ff: fe03: 14d0. In addition to "port of concern," the address of the line for the IPv6 address.

IPv6 is not currently widely used in the world, currently in some countries (in Asia) used more often, some advanced operating systems support IPv6. Nmap IPv6 functionality using scanning source and destination IPv6 need to be configured. If the ISP (mostly) does not allocate IPv6 addresses, Nmap can be used free tunnel broker. A preferred option is to BT Exact, located [https://tb.ipv6.btexact.com/](https://tb.ipv6.btexact.com/). In addition, Hurricane Electric, located [http://ipv6tb.he.net/](http://ipv6tb.he.net/). 6to4 tunnels are another popular free methods.

** - A (intense scan mode option) **

This option enables additional advanced and high-strength options, has yet to determine the contents represent. Currently, this option is enabled operating system detection (-O) and version scanning (-sV), the future will add more features. The purpose is to enable a comprehensive set of scanning options, the user does not need to remember a lot of options. This option is only enabled features, options may not contain a time required (such as -T4) or details option (-v).

** - datadir <directoryname> (described Nmap user position data file) **

Nmap obtain runtime data from a special file, which file has nmap-service-probes, nmap-services, nmap-protocols, nmap-rpc, nmap-mac-prefixes and nmap-os-fingerprints. Nmap first find these files in the directory --datadir options explained. File not found, it looks in the directory BMAPDIR environment variable note. Next is a real and effective UID of ~ / .nmap Nmap executable code or location (only the Win32); then compiled location, such as / usr / local / share / nmap or / usr / share / nmap. Nmap find the last position of the current directory.

** - send-eth (to use the original Ethernet frame transmitted) **

Nmap requires Ethernet packet transmission (data link) layer rather than the IP (network layer). Under default, Nmap select the most suitable way to its operating platform, the original sockets (IP layer) is the most effective way to UNIX hosts, and Ethernet frame most suitable for the Windows operating system, since Microsoft disabled raw socket support. In UNIX, if no other options (such as no Ethernet connection), regardless of whether there is the option, Nmap uses raw IP packets.

** - send-ip (Send the original IP layer) **

Nmap required by the original IP sockets to send a message, rather than low-level Ethernet frame. This is in addition --send-eth option.

** - privileged (assuming the user has full rights) **

Tell Nmap assumed to have sufficient rights to source socket packet transmission, packet capturing and user's operation authority UNIX-like root systems. By default, if a similar operation by the getuid () request is not 0, Nmap exits. --privileged extremely efficient system having a similar property in the Linux kernel, the system is configured to allow non-privileged users can scan the original packet. To be clear, the use of these privileges required before the Other Options (SYN scan, OS detection, etc.). Nmap-PRIVILEGED variable is set equivalent to --privileged options.

** - V; --version (Print version information) **

Print Nmap version number and exit.

** - h; --help (Print help summary surface) **

Print a short help screen lists the most commonly used command options, this function without arguments Nmap is same.

Run-time interactive # #

* Nmap does not currently have this functionality, this section may be added or deleted. *

In the implementation of Nmap, all keystrokes are recorded. This allows users without the need to restart the program to terminate or interact with. Specific key to change the option, other keys will output a status message about the scan. Agreed as follows, lowercase letters increase print volume, reduce print volume in capital letters.

** v / V **
Increase / decrease details

** d / D **
Increase / decrease the debugging level

** p / P **
Open / Close packet trace

other
Print information similar to this:

Stats: 0:00:08 elapsed; 111 hosts completed (5 up), 5 undergoing Service Scan

Service scan Timing: About 28.00% done; ETC: 16:18 (0:00:15 remaining)

Example # #

Some examples are given below, simple to complex esoteric. More specific, some examples of the use of actual IP addresses and domain names. In these locations, you can use your own network address / domain name replacement. Note that the scanning other networks is not necessarily illegal, some network administrators do not want to see the scan is not requested, will produce complain. So, first get the permission is the best way.

If it is for the test, scanme.nmap.org allowed to be scanned. But only allows the use Nmap to scan and test ban loophole or DoS attacks. In order to ensure the bandwidth, scanning the host of not more than 12 times a day. If this free scanning services to abuse, the system will crash and Nmap will report to resolve the specified host name / IP address failed: scanme.nmap.org. These requirements also apply to scan free scanme2.nmap.org, scanme3.nmap.org and so on, though those hosts do not currently exist.

** nmap -v scanme.nmap.org **

All reserved TCP port scan the host scanme.nmap.org in this option. -v option to enable the detail mode.

** nmap -sS -O scanme.nmap.org/24**

Secret SYN scan, where the object is a host Saznme "C class" network of 255 hosts. While trying to determine the type of operating system each working host. Because carried SYN scan and OS detection, the scan need to have root privileges.

** nmap -sV -p 22,53,110,143,4564 198.116.0-255.1-127 **

TCP and a host include scanning the object class B 188.116 segment 255 8-bit subnet. This test is used to determine whether the system is running sshd, DNS, imapd or 4564 port. If these ports are open, version detection is used to determine which application is running.

** nmap -v -iR 100000 -P0 -p 80 **

100,000 randomly selected hosts scanning is running a Web server (port 80). Sent by the initial stage of probe packets to determine whether the host is working very wasteful of time and only detect the host of a port, so using -P0 prohibited list of hosts.

** nmap -P0 -p80 -oX logs / pb-port80scan.xml -oG logs / pb-port80scan.gnmap 216.163.128.20/20**

Scan 4096 IP addresses, to find a Web server (not ping), to save the results Grep and XML format.

** host -l company.com | cut -d -f 4 | nmap -v -iL **

A DNS zone transfer to find the host company.com, then the IP address to Nmap. The above command for GNU / Linux - have different command systems for other transmission area.

 
