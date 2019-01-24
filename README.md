# HuaweiB525Router
Python3 code to interact with the API for the Huawei B525 router (tested on model B525s-65a)

This implemented the SCAM authentication model Huawei are using on some routers.<br>
Based on the initial code from Marcin: https://github.com/mkorz/b618reboot

Untested but this may also work (or be able to be leveraged) for:
- B618s-22d
- B715s-23c

Usage is as follows:
```
router = B525Router(router='192.168.8.1', username='admin', password='xxx')
router.getInfo() //Calls http://192.168.8.1/api/device/information
```

Which returns:
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
getMACFilter()  => api/security/mac-filter

POST Requests
-------------
doReboot()      => api/device/control
doPowerOff()    => api/device/control

setDenyMacFilter(macs)  => api/security/mac-filter
clearMacFilter()        => api/security/mac-filter
```


    
