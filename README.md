# HuaweiB525Router
Python2 code to interact with the API for the Huawei B525 router (tested on model B525s-65a)

This implemented the SCAM authentication model Huawei are using on some routers.<br>
Based on the initial code from Marcin: https://github.com/mkorz/b618reboot

Untested but this may also work (or be able to be leveraged) for:
- B618s-22d
- B715s-23c

Currently supported calls:
```
GET Requests
----------
getInfo()       => api/device/information
getTraffic()    => api/monitoring/traffic-statistics
getStats()      => api/monitoring/month_statistics")
getClients()    => api/wlan/host-list
getAllClients() => api/lan/HostInfo
getSignal()     => api/device/signal
getMacFilter()  => api/security/mac-filter
getLanSettings()=> api/dhcp/settings
getStaticHosts()=> api/dhcp/static-addr-info

POST Requests
-------------
doReboot()
doPowerOff()
setDenyMacFilter(macs)
setAllowMacFilter(macs)
setMacFilterOff()
setDhcpOff()
setDhcpOn(startAddress, endAddress, leaseTime=86400)
setLanAddress(ipaddress, netmask='255.255.255.0', url='homerouter.cpe')
setManualDns(primaryDns, secondaryDns='')
setAutomaticDns()
setAllLanSettings(settings)
setStaticHosts(settings)
```

Example usage is as follows:
```
router = B525Router(router='192.168.8.1', username='admin', password='xxx')

#Get Router information, example result below.
router.getInfo()

#Set DNS to Google
router.setManualDns('8.8.8.8', '8.8.4.4')

#Deny macs
router.setDenyMacFilter(['xx:xx:xx:xx:xx:xx','yy:yy:yy:yy:yy:yy', ...])


```

Router information returned from getInfo():
```
<response>
<DeviceName>B525s-65a</DeviceName>
<SerialNumber>xxx</SerialNumber>
<Imei>xxx</Imei>
<Imsi>xxx</Imsi>
<Iccid>xxx</Iccid>
<Msisdn/>
<HardwareVersion>WL2B520M</HardwareVersion>
<SoftwareVersion>11.189.63.00.74</SoftwareVersion>
<WebUIVersion>21.100.44.00.03</WebUIVersion>
<MacAddress1>XX:XX:XX:XX:XX:XX</MacAddress1>
<MacAddress2/>
<WanIPAddress>99.99.99.99</WanIPAddress>
<wan_dns_address>99.99.99.99,99.99.99.99</wan_dns_address>
<WanIPv6Address/>
<wan_ipv6_dns_address/>
<ProductFamily>LTE</ProductFamily>
<Classify>cpe</Classify>
<supportmode>LTE|WCDMA|GSM</supportmode>
<workmode>LTE</workmode>
<submask>255.255.255.255</submask>
</response>
```



    
