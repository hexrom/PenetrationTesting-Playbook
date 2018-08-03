### Network Security  
#### 1.1 Information Gathering
_1.1.1 Passive Recon_  

WhoIs Look-ups
```
$ whois domain.com
or
$ sudo nmap --script whois-domain domain.com -sn
```
DNS Enumeration  
Queries w/ Nslookup
```
$ Nslookup -query=<Arg(any/MX/NS)> domain.com
or interactive
$ nslookup
>set q=<Arg(A/MX/NS)>
>domain.com
```
Queries and Zonetransfers w/ Dig
```
$ Dig +nocmd domain.com <Arg(MX/NS/A)> +noall +answer
$ Dig +nocmd domain.com AXFR +noall +answer @domain.com - Zone Transfer
```
Other Options for DNS Enumeration
```
$ fierce -dns domain.com
$ dnsrecon -d domain.com
$ dnsmap domain.com
```

_1.1.2 Host Discovery_  
**Basic**
Nmap
```
$ sudo nmap -sn targetIP --disable-arp-ping
$ sudo nmap -sn -P<Arg(S/A)> targetIP --disable-arp-ping - TCP packet with SYN or ACK flag
$ sudo nmap -sn -PE targetIP --disable-arp-ping - ICMP echo request
$ sudo nmap -sn -PP targetIP --disable-arp-ping - Timestamp request
```
FPing
```
$ fping -A targetIP -e - send ICMP echo packet, check if alive
$ fping -q -a -g target/24 -r 0 -e - send ICMP echo to subnet with no retries in quiet mode, only show if alive
```
HPing3
```
$ sudo hping3 -F -P -U target -c 3 - Xmas discovery scan, RA flag
$ sudo hping3 -1 192.168.1.x --rand-dest -I eth2 - host discovery on subnet on specificed interface
```
