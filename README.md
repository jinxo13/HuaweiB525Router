# Huawei B525 Router Python API
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
- For Optus Australia users allows setting DNS and Port Forwarding which is eith hidden or disabled in the Web UI

## Example usage
```
   from router import B525Router
   import xmlobjects
   
   #Connect to the router
   router = B525Router(router='192.168.8.1', username='admin', password='xxx')

   #Get a list of what API calls appear to be are supported (GET requests only)
   response = router.testFeatures()

   #Get the router detailed information
   response = router.device.getInfo() #Calls http://192.168.8.1/api/device/information

   #Reboot
   response = router.device.doReboot()

   #Configure MAC filtering to blacklist MAC addresses
   response = router.security.setDenyMacFilter(['XX:XX:XX:XX:XX:XX', 'YY:YY:YY:YY:YY:YY'])

   #Make a custom GET API call
   response = router.api('api/device/information')

   #Make a custom POST API call, does a reboot
   request = '<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>'
   response = router.api('api/device/control', request)

   #Set up port forwarding to an IPSEC VPN server
   config = xmlobjects.VirtualServers()
   config.addUdpService('IPSEC1',500,500,'192.168.8.11')
   config.addUdpService('IPSEC2',4500,4500,'192.168.8.11')
   response = router.wan.setVirtualServer(config)

   #Configure some LAN settings
   config = xmlobjects.LanSettings()
   config.setDnsManual('192.168.8.11','192.168.8.1')
   config.setLanAddress('192.168.8.1','255.255.255.0','homerouter.cpe')
   config.setDhcpOn('192.168.8.100','192.168.8.200',86400)
   response = router.lan.setAllLanSettings(config)

   #Setup some static hosts
   config = xmlobjects.StaticHosts()
   config.addHost('e7:4e:08:31:61:ba','192.168.8.11')
   config.addHost('b8:29:eb:dd:0d:c1','192.168.8.10')
   config.addHost('f0:03:8f:b3:1c:9a','192.168.8.12')
   response = router.lan.setStaticHosts(config)

   #Logout
   response = router.logout()
```

Here's an example reponse (for ```getInfo()```):
```
<?xml version="1.0" encoding="UTF-8"?>
<response>
   <DeviceName>B525s-65a</DeviceName>
   <SerialNumber>xxx</SerialNumber>
   <Imei>xxx</Imei>
   <Imsi>xxx</Imsi>
   <Iccid>xxx</Iccid>
   <Msisdn />
   <HardwareVersion>WL2B520M</HardwareVersion>
   <SoftwareVersion>11.189.63.00.74</SoftwareVersion>
   <WebUIVersion>21.100.44.00.03</WebUIVersion>
   <MacAddress1>XX:XX:XX:XX:XX:XX</MacAddress1>
   <MacAddress2 />
   <WanIPAddress>99.99.99.99</WanIPAddress>
   <wan_dns_address>99.99.99.99,99.99.99.99</wan_dns_address>
   <WanIPv6Address />
   <wan_ipv6_dns_address />
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
device.getInfo()           => api/device/information
device.getSignal()         => api/device/signal
device.getBridgeMode()     => api/security/bridgemode (Not supported on B525)
device.getCircleLed()      => api/led/circle-switch (Not supported on B525)
device.getSignalStrength() => Custom - returns signal strength between 0 and 5 based on rsrp value

monitoring.getTraffic()    => api/monitoring/traffic-statistics
monitoring.getStats()      => api/monitoring/month_statistics")

lan.getClients()           => api/wlan/host-list
lan.getAllClients()        => api/lan/HostInfo
lan.getLanSettings()       => api/dhcp/settings
lan.getStaticHosts()       => api/dhcp/static-addr-info

security.getTimeRule()     => api/timerule/timerule (Not supported on B525)
security.getMacFilter()    => api/security/mac-filter

wan.getVirtualServers()    => api/security/virtual-servers

POST Requests
-------------
logout()

device.doReboot()
device.doPowerOff()

security.setDenyMacFilter(macs)
security.setAllowMacFilter(macs)
security.setMacFilterOff()

lan.setDhcpOff()
lan.setDhcpOn(startAddress, endAddress, leaseTime=86400)
lan.setLanAddress(ipaddress, netmask='255.255.255.0', url='homerouter.cpe')
lan.setManualDns(primaryDns, secondaryDns='')
lan.setAutomaticDns()
lan.setAllLanSettings(settings)
lan.setStaticHosts(settings)

montitoring.clearTrafficStats()

wan.setVirtualServers(servers)
wan.clearVirtualServers()
```

## Results of testFeatures() for B525-65a
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
