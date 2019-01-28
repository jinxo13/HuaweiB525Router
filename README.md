# HuaweiB525Router
Python2 code to interact with the underlying API for the Huawei B525 router (tested on model B525s-65a).
This is bascially a proxy for the API calls with some additional features.
The API responses are in XML.

Untested but this may also work (or be able to be leveraged) for:
- B618s-22d
- B715s-23c

You can use the ```testFeatures``` function to determine what is supported for your router.

## Features
- SCRAM authentication model Huawei are using on some routers - based on the initial code from Marcin: https://github.com/mkorz/b618reboot
- Injected error messages in router API responses when missing (refer to errors.py for the list)
- Additional custom API calls like getSignalStrength() - returns strength rating of 0 - 5

## Example usage
```
    #Connect to the router
    router = B525Router(router='192.168.8.1', username='admin', password='xxx')

    #Get a list of what API calls appear to be are supported (GET requests only)
    response = router.testFeatures()

    #Get the router detailed information
    response = router.getInfo() #Calls http://192.168.8.1/api/device/information

    #Reboot
    response = router.reboot()

    #Configure MAC filtering to blacklist MAC addresses
    response = router.setDenyMacFilter(['XX:XX:XX:XX:XX:XX', 'YY:YY:YY:YY:YY:YY'])

    #Make a custom GET API call
    response = router.api('api/device/information')

    #Make a custom POST API call, does a reboot
    request = '<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>'
    response = router.api('api/device/control', request)

    #Logout
    response = router.logout()
```

Here's an example reponse (for ```getInfo()```):
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

## Supported Calls
Direct GET and POST API calls can be made as well, as shown in the Example Usage above.
```
GET Requests
----------
getInfo()           => api/device/information
getTraffic()        => api/monitoring/traffic-statistics
getStats()          => api/monitoring/month_statistics")
getClients()        => api/wlan/host-list
getAllClients()     => api/lan/HostInfo
getSignal()         => api/device/signal
getMacFilter()      => api/security/mac-filter
getLanSettings()    => api/dhcp/settings
getStaticHosts()    => api/dhcp/static-addr-info
getBridgeMode()     => api/security/bridgemode (Not supported on B525)
getTimeRule()       => api/timerule/timerule (Not supported on B525)
getCircleLed()      => api/led/circle-switch (Not supported on B525)
getSignalStrength() => Custom - returns signal strength between 0 and 5 based on rsrp value

POST Requests
-------------
doReboot()
doPowerOff()
logout()
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
clearTrafficStats()
```

## Results of testFeatuires() for B525-65a
```
<?xml version="1.0" encoding="UTF-8"?>
<response>
   <DeviceName>B525s-65a</DeviceName>
   <ProductFamily>LTE</ProductFamily>
   <HardwareVersion>WL2B520M</HardwareVersion>
   <SoftwareVersion>11.189.63.00.74</SoftwareVersion>
   <WebUIVersion>21.100.44.00.03</WebUIVersion>
   <MacAddress1>D0:16:B4:F2:30:92</MacAddress1>
   <MacAddress2 />
   <Failed>
      <Function>
         <Url>api/led/circle-switch</Url>
         <Name>getCircleLed</Name>
         <Error>100006: Parameter error</Error>
      </Function>
      <Function>
         <Url>api/timerule/timerule</Url>
         <Name>getTimeRule</Name>
         <Error>100006: Parameter error</Error>
      </Function>
      <Function>
         <Url>api/security/bridgemode</Url>
         <Name>getBridgeMode</Name>
         <Error>100002: The router does not support this function</Error>
      </Function>
   </Failed>
   <Passed>
      <Function>
         <Url>api/dhcp/static-addr-info</Url>
         <Name>getStaticHosts</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/wlan/host-list</Url>
         <Name>getClients</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/user/history-login</Url>
         <Name>getUserHistory</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/lan/HostInfo</Url>
         <Name>getAllClients</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/device/information</Url>
         <Name>getInfo</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/dhcp/settings</Url>
         <Name>getLanSettings</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/device/signal</Url>
         <Name>getSignal</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/monitoring/month_statistics</Url>
         <Name>getStats</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/monitoring/traffic-statistics</Url>
         <Name>getTraffic</Name>
         <Error />
      </Function>
      <Function>
         <Url>api/security/mac-filter</Url>
         <Name>getMacFilter</Name>
         <Error />
      </Function>
   </Passed>
</response>
```
