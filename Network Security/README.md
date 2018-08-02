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

```
$ Nslookup -query=any domain.com
or
>nslookup
>server <target>
>set q=NS
>set q=MX
>domain.com
>ns1.domain.com
```
Queries and Zonetransfers w/ Dig
```
$ Dig domain.com A  (Query "A" Record of a domain)  
$ Dig +nocmd domain.com AXFR +noall +answer @serverIP  (Zone Transfer)  
$ Dig @serverIP domain.com -t AXFR +nocookie  (Zone Transfer)  
```
Find subdomains, zone transfer, dns enumeration etc. w/ Fierce
```
$ Fierce -dns domain.com 
```
Bruteforce subdomains w/ DNSMap
```
$ Dnsmap domain.com
```

