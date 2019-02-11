# Huawei B525 Router Python API
Python2 code to interact with the underlying API for the Huawei B525 router (tested on model B525s-65a).
This iimplements a proxy for the API calls with some additional features.
The API responses are in XML.
Any errors in the API calls are also returned in XML.

Untested but this may also work (or be able to be leveraged) for:
- B618s-22d
- B715s-23c

You can use the ```router.features``` function to determine what is supported for your router.

## Features
- The test_features function will provide information about what API calls are supported by the router
- SCRAM authentication model Huawei are using on some routers - based on the initial code from Marcin: https://github.com/mkorz/b618reboot
- Injected error messages in router API responses when missing (refer to errors.py for the list)
- Additional custom API calls like ```router.device.signal_strength``` - returns strength rating of 0 - 5
- Support settings where the router requires an encrypted request

## Example usage
```python
   import huawei_lte.router as lte
   import huawei_lte.xmlobjects as xmlobjects
   from huawei_lte.errors import RouterError
   
   #Connect to the router
   router = lte.B525Router('192.168.8.1')
   router.login(username='admin', password='xxx') #Throws RouterError on a login error


   #Get a list of what API calls appear to be are supported (GET requests only)
   response = router.features

   #Get the router detailed information
   response = router.device.info

   #Commands
   response = router.device.do_reboot()
   response = router.device.do_poweroff()

   #Custom API calls
   response = router.api('device/information') #GET call to http://<host>/api/device/information
   response = router.api('device/control', {'Control': 1}) #Sends the XML request as below
   response = router.api(url='device/control', data={'Control': 1}, encrypted=True) #Send an encrypted payload
   #Send the raw XML
   request = '<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>'
   response = router.api('device/control', request)

   #Returns various information from the router
   response = router.device.info
   response = router.device.signal
   response = router.device.signal_strength #CUSTOM: Alternate signal strength determination
   response = router.device.circleled #not available on Optus B525
   response = router.device.status #Various device status values

   response = router.monitoring.traffic #Current traffic
   response = router.monitoring.stats #Monthly statistics
   response = router.monitoring.trafficalert #Monthly data alert settings
   response = router.monitoring.notifications

   response = router.security.timerule #Not available on Optus B525
   response = router.security.bridgemode #Not available on Optus B525

   response = route.user.last_login

   response = router.lan.clients #Currently connected clients
   response = router.lan.all_clients #All known clients
   response = router.lan.settings
   response = router.lan.static_hosts

   response = router.wan.port_forwards

   response = router.net.mode #Current supported 2G/3G/4G mode and bands
   response = router.net.modelist #Expanded list of supported bands, contains non-XML value lists
   response = router.net.modelist2 #CUSTOM: Provides an XML format friendly expanded list

   #Manage 2G/3G/4G options
   response = router.net.set_network_mode({'mode': 'AUTO'})
   response = router.net.set_network_mode({'mode': '2G'})
   response = router.net.set_network_mode({'mode': '3G'})
   response = router.net.set_network_mode({'mode': '4G'})
   response = router.net.set_lte_band({'bands': ['B40', 'B28', 'B7', 'B1', 'B3', 'B8']})
   response = router.net.set_network_band({'bands': ['W2100', 'GSM900', 'W850', 'GSM1800', 'GSM850', 'GSM1900', 'W1900', 'W900']})

   #Manage port forwarding
   response = router.wan.port_forwards
   response = router.wan.add_port_forward({
      'name':'IPSEC1',
      'startwanport':500,
      'startlanport':500,
      'localip': '192.168.8.11',
      'protocol': 'UDP'})
   response = router.wan.add_port_forward({
      'name':'IPSEC2',
      'startwanport':4500,
      'startlanport':4500,
      'localip': '192.168.8.11',
      'protocol': 'UDP'})
   response = router.wan.remove_port_forward({'name': 'IPSEC1'})
   response = router.wan.clear_port_forwards()

   #Manage LAN settings
   response = router.lan.settings
   response = router.lan.set_dns_auto() #DNS set automatically by router
   response = router.lan.set_dns({'primary': '192.168.8.11', 'secondary': '192.168.8.1'})
   response = router.lan.set_ipaddress({'ipaddress': '192.168.8.1', 'netmask': '255.255.255.0'}) #Sets the routers LAN IP Address
   response = router.lan.set_dhcp({'startaddress':'192.168.8.100', 'endaddress': '192.168.8.200'})
   response = router.lan.set_dhcp_off()
   
   #Manage static IP assignment
   response = router.lan.add_static_host([
      {'macaddress': '92:1b:46:9d:be:86', 'ipaddress': '192.168.8.100'},
      {'macaddress': '92:1b:46:9d:be:87', 'ipaddress': '192.168.8.102'}
      ])
   response = router.lan.remove_static_host({'macaddress': '92:1b:46:9d:be:86'})
   response = router.lan.clear_static_hosts()

   #Manage MAC filtering
   response = router.security.macfilter
   #Set filtering to Deny mode
   response = router.security.deny_macaddress(['92:1b:46:9d:be:86', '92:1b:46:9d:be:87'])
   #Set filtering to Allow mode
   response = router.security.allow_macaddress(['92:1b:46:9d:be:86', '92:1b:46:9d:be:87'])
   response = router.security.set_macfilter_off()

   #Manage DDNS settings
   response = router.wan.ddns
   response = router.wan.add_ddns({
      'username': 'bilbo.baggins@gmail.com',
      'password': 'elevenses',
      'domain': 'bilbo.ddns.net',
      'provider': 'No-IP.com'
   })
   response = router.wan.remove_ddns({'domain': 'bilbo.ddns.net'})
   #Change the DDNS password
   response = router.wan.edit_ddns({
      'username': 'bilbo.baggins@gmail.com',
      'password': 'smaug_rules',
      'domain': 'bilbo.ddns.net',
      'provider': 'No-IP.com'
   })

   #Manage monitoring
   response = router.monitoring.clear_stats()
   response = router.monitoring.set_trafficalert({
      'startday': 8, #Plan starts on the 8th of each month
      'datalimit': '500GB', #500GB Monthly data limit - can be specified in MB, GB
      'threshold': 90 #Alert at 90% of usage
      })

   #Logout
   response = router.logout() #Throws RouterError on a logout error
```

Here's an example reponse (for ```router.device.info```):
```xml
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

## Results of ```router.features``` for B525-65a
```xml
<?xml version="1.0" encoding="UTF-8"?>
<response>
   <DeviceName>B525s-65a</DeviceName>
   <ProductFamily>LTE</ProductFamily>
   <HardwareVersion>WL2B520M</HardwareVersion>
   <SoftwareVersion>11.189.63.00.74</SoftwareVersion>
   <WebUIVersion>21.100.44.00.03</WebUIVersion>
   <MacAddress1>XX:XX:XX:XX:XX:XX</MacAddress1>
   <MacAddress2 />
   <Failed>
      <Function>
         <Name>device.circleled</Name>
         <Url>api/led/circle-switch</Url>
         <Error>100006: Parameter error</Error>
      </Function>
      <Function>
         <Name>security.timerule</Name>
         <Url>api/timerule/timerule</Url>
         <Error>100006: Parameter error</Error>
      </Function>
      <Function>
         <Name>device.bridgemode</Name>
         <Url>api/security/bridgemode</Url>
         <Error>100002: The router does not support this function</Error>
      </Function>
   </Failed>
   <Passed>
      <Function>
         <Name>device.info</Name>
         <Url>api/device/information</Url>
      </Function>
      <Function>
         <Name>lan.current_clients</Name>
         <Url>api/wlan/host-list</Url>
      </Function>
      <Function>
         <Name>monitoring.trafficalert</Name>
         <Url>api/monitoring/start_date</Url>
      </Function>
      <Function>
         <Name>monitoring.stats</Name>
         <Url>api/monitoring/month_statistics</Url>
      </Function>
      <Function>
         <Name>security.macfilter</Name>
         <Url>api/security/mac-filter</Url>
      </Function>
      <Function>
         <Name>lan.settings</Name>
         <Url>api/dhcp/settings</Url>
      </Function>
      <Function>
         <Name>lan.static_hosts</Name>
         <Url>api/dhcp/static-addr-info</Url>
      </Function>
      <Function>
         <Name>lan.all_clients</Name>
         <Url>api/lan/HostInfo</Url>
      </Function>
      <Function>
         <Name>device.status</Name>
         <Url>api/monitoring/status</Url>
      </Function>
      <Function>
         <Name>user.last_login</Name>
         <Url>api/user/history-login</Url>
      </Function>
      <Function>
         <Name>wan.ddns</Name>
         <Url>api/ddns/ddns-list</Url>
      </Function>
      <Function>
         <Name>monitoring.traffic</Name>
         <Url>api/monitoring/traffic-statistics</Url>
      </Function>
      <Function>
         <Name>wan.port_forwards</Name>
         <Url>api/security/virtual-servers</Url>
      </Function>
      <Function>
         <Name>device.signal</Name>
         <Url>api/device/signal</Url>
      </Function>
      <Function>
         <Name>monitoring.notifications</Name>
         <Url>api/monitoring/check-notifications</Url>
      </Function>
   </Passed>
</response
```
