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
- The ```features``` function will provide information about what API calls are supported by the router
- SCRAM authentication model Huawei are using on some routers
- Injected error messages in router API responses when missing (refer to errors.py for the list)
- Additional custom API calls like ```router.device.signal_strength``` - returns strength rating of 0 - 5
- Support settings where the router requires an encrypted request

## References
- SCRAM authentication code based on the initial code from Marcin: https://github.com/mkorz/b618reboot
- Aproach to investigating the API - https://www.mrt-prodz.com/blog/view/2015/05/huawei-modem-api-and-data-plan-monitor
- API Error codes - https://github.com/HSPDev/Huawei-E5180-API
- Additional APi and Web UI info - http://www.bez-kabli.pl/viewtopic.php?t=42168

## Example usage
```python
   import huawei_lte.router as lte
   import huawei_lte.xmlobjects as xmlobjects
   from huawei_lte.errors import RouterError
   
   #Connect to the router
   router = lte.B525Router('192.168.8.1')
   router.login(username='admin', password='xxx') #Throws RouterError on a login error


   #Get a list of what API calls appear to be are supported (GET requests only)
   router.features

   #Get the router detailed information
   router.device.info

   #Commands
   router.device.do_reboot()
   router.device.do_poweroff()

   #Custom API calls
   router.api('device/information') #GET call to http://<host>/api/device/information
   router.api('device/control', {'Control': 1}) #Sends the XML request as below
   router.api(url='device/control', data={'Control': 1}, encrypted=True) #Send an encrypted payload
   #Send the raw XML
   request = '<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>'
   router.api('device/control', request)

   #Returns various information from the router
   router.device.info
   router.device.signal
   router.device.signal_strength #CUSTOM: Alternate signal strength determination
   router.device.circleled #not available on Optus B525
   router.device.status #Various device status values

   router.monitoring.traffic #Current traffic
   router.monitoring.stats #Monthly statistics
   router.monitoring.trafficalert #Monthly data alert settings
   router.monitoring.notifications

   router.security.timerule #Not available on Optus B525
   router.security.bridgemode #Not available on Optus B525

   route.user.last_login

   router.lan.clients #Currently connected clients
   router.lan.all_clients #All known clients
   router.lan.settings
   router.lan.static_hosts

   router.wan.port_forwards

   router.net.mode #Current supported 2G/3G/4G mode and bands
   router.net.modelist #Expanded list of supported bands, contains non-XML value lists
   router.net.modelist2 #CUSTOM: Provides an XML format friendly expanded list

   #Manage 2G/3G/4G options
   router.net.set_network_mode({'mode': 'AUTO'})
   router.net.set_network_mode({'mode': '2G'})
   router.net.set_network_mode({'mode': '3G'})
   router.net.set_network_mode({'mode': '4G'})
   router.net.set_lte_band({'bands': ['B40', 'B28', 'B7', 'B1', 'B3', 'B8']})
   router.net.set_network_band({'bands': ['W2100', 'GSM900', 'W850', 'GSM1800', 'GSM850', 'GSM1900', 'W1900', 'W900']})

   #Manage port forwarding
   router.wan.port_forwards
   router.wan.add_port_forward({
      'name':'IPSEC1',
      'startwanport':500,
      'startlanport':500,
      'localip': '192.168.8.11',
      'protocol': 'UDP'})
   router.wan.add_port_forward({
      'name':'IPSEC2',
      'startwanport':4500,
      'startlanport':4500,
      'localip': '192.168.8.11',
      'protocol': 'UDP'})
   router.wan.remove_port_forward({'name': 'IPSEC1'})
   router.wan.clear_port_forwards()

   #Manage LAN settings
   router.lan.settings
   router.lan.set_dns_auto() #DNS set automatically by router
   router.lan.set_dns({'primary': '192.168.8.11', 'secondary': '192.168.8.1'})
   router.lan.set_ipaddress({'ipaddress': '192.168.8.1', 'netmask': '255.255.255.0'}) #Sets the routers LAN IP Address
   router.lan.set_dhcp({'startaddress':'192.168.8.100', 'endaddress': '192.168.8.200'})
   router.lan.set_dhcp_off()
   
   #Manage static IP assignment
   router.lan.add_static_host([
      {'macaddress': '92:1b:46:9d:be:86', 'ipaddress': '192.168.8.100'},
      {'macaddress': '92:1b:46:9d:be:87', 'ipaddress': '192.168.8.102'}
      ])
   router.lan.remove_static_host({'macaddress': '92:1b:46:9d:be:86'})
   router.lan.clear_static_hosts()

   #Manage MAC filtering
   router.security.macfilter
   #Set filtering to Deny mode
   router.security.deny_macaddress(['92:1b:46:9d:be:86', '92:1b:46:9d:be:87'])
   #Set filtering to Allow mode
   router.security.allow_macaddress(['92:1b:46:9d:be:86', '92:1b:46:9d:be:87'])
   router.security.set_macfilter_off()

   #Manage DDNS settings
   router.wan.ddns
   router.wan.add_ddns({
      'username': 'bilbo.baggins@gmail.com',
      'password': 'elevenses',
      'domain': 'bilbo.ddns.net',
      'provider': 'No-IP.com'
   })
   router.wan.remove_ddns({'domain': 'bilbo.ddns.net'})
   #Change the DDNS password
   router.wan.edit_ddns({
      'username': 'bilbo.baggins@gmail.com',
      'password': 'smaug_rules',
      'domain': 'bilbo.ddns.net',
      'provider': 'No-IP.com'
   })

   #Manage VOIP
   #I don't have VOIP enabled on my router so haven't tested these
   router.voip.status #Returns <response>Idle</response> or <response>Busy</response>
   router.voip.sip_accounts #Current configured SIP accounts
   router.voip.sip_options #Call waiting enabled or not
   router.voip.sip_server #Return current SIP server settings
   router.voip.voice_settings #Return Caller ID Send Type and key tones (Dual Tone Multi-frequency - DTMF) type

   router.voip.set_sip_options({'callwaiting': 1}) #Turn call waiting on/off
   router.voip.add_account({'account': '041232345', 'username': 'fred', 'password': 'xxxx'}) #Add a SIP account
   router.voip.remove_account({'account': '041232345'}) #Remove a SIP account
   router.voip.voice_settings({'cid_send_type': 'FSK', 'cs_dtmf_method': 'INBAND'})

   #Manage monitoring
   router.monitoring.clear_stats()
   router.monitoring.set_trafficalert({
      'startday': 8, #Plan starts on the 8th of each month
      'datalimit': '500GB', #500GB Monthly data limit - can be specified in MB, GB
      'threshold': 90 #Alert at 90% of usage
      })

   #Change Ethernet settings
   router.ethernet.status #current ethernet connection status
   router.ethernet.connection #Friendly mode and connection state information
   router.ethernet.settings #Current ethernet settings

   #Automatically select the best ethernet mode (recommended default)
   router.ethernet.set_auto()
   #You can set all the settings below (apart from the static info)
   router.ethernet.set_auto({'username': 'fred', 'password': 'secret', 'authmode': 0})

   #LTE mode - so uses 3G or 4G
   router.ethernet.set_lan_only()
   
   #Connect with PPPOE 0=AUTO, 1=PAP, 2=CHAP
   router.ethernet.set_pppoe({'username': 'fred', 'password': 'secret', 'authmode': 0})
   
   #An IP address is provided automatically
   router.ethernet.set_dynamic() 
   #Get an assinged IP Address but override the provided DNS settings
   router.ethernet.set_dynamic({'primarydns': '8.8.8.8', 'secondarydns':'8.8.4.4'})
   #Use either PPOE or an assigned IP Address
   router.ethernet.set_ppoe_dynamic() 
   
   #Use a static IP Address
   router.ethernet.set_static({'ipaddress': '192.168.1.3', 'netmask': '255.255.255.0', 'gateway': '192.168.1.1', 'primarydns': '8.8.8.8', 'secondarydns': '8.8.4.4'})

   #Logout
   router.logout() #Throws RouterError on a logout error
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
   <MacAddress1>D0:16:B4:F2:30:92</MacAddress1>
   <MacAddress2 />
   <Failed>
      <Function>
         <Name>device.circleled</Name>
         <Url>api/led/circle-switch</Url>
         <Error>100006: Parameter error</Error>
      </Function>
      <Function>
         <Name>device.bridgemode</Name>
         <Url>api/security/bridgemode</Url>
         <Error>100002: No such URL. The router does not support this function</Error>
      </Function>
      <Function>
         <Name>security.timerule</Name>
         <Url>api/timerule/timerule</Url>
         <Error>100006: Parameter error</Error>
      </Function>
   </Failed>
   <Passed>
      <Function>
         <Name>lan.settings</Name>
         <Url>api/dhcp/settings</Url>
      </Function>
      <Function>
         <Name>lan.static_hosts</Name>
         <Url>api/dhcp/static-addr-info</Url>
      </Function>
      <Function>
         <Name>lan.clients</Name>
         <Url>api/wlan/host-list</Url>
      </Function>
      <Function>
         <Name>lan.all_clients</Name>
         <Url>api/lan/HostInfo</Url>
      </Function>
      <Function>
         <Name>user.last_login</Name>
         <Url>api/user/history-login</Url>
      </Function>
      <Function>
         <Name>ethernet.settings</Name>
         <Url>api/cradle/basic-info</Url>
      </Function>
      <Function>
         <Name>ethernet.status</Name>
         <Url>api/cradle/status-info</Url>
      </Function>
      <Function>
         <Name>device.info</Name>
         <Url>api/device/information</Url>
      </Function>
      <Function>
         <Name>device.signal</Name>
         <Url>api/device/signal</Url>
      </Function>
      <Function>
         <Name>device.status</Name>
         <Url>api/monitoring/status</Url>
      </Function>
      <Function>
         <Name>network.mode</Name>
         <Url>api/net/net-mode</Url>
      </Function>
      <Function>
         <Name>network.modelist</Name>
         <Url>api/net/net-mode-list</Url>
      </Function>
      <Function>
         <Name>security.macfilter</Name>
         <Url>api/security/mac-filter</Url>
      </Function>
      <Function>
         <Name>monitoring.traffic</Name>
         <Url>api/monitoring/traffic-statistics</Url>
      </Function>
      <Function>
         <Name>monitoring.stats</Name>
         <Url>api/monitoring/month_statistics</Url>
      </Function>
      <Function>
         <Name>monitoring.notifications</Name>
         <Url>api/monitoring/check-notifications</Url>
      </Function>
      <Function>
         <Name>monitoring.trafficalert</Name>
         <Url>api/monitoring/start_date</Url>
      </Function>
      <Function>
         <Name>wan.port_forwards</Name>
         <Url>api/security/virtual-servers</Url>
      </Function>
      <Function>
         <Name>wan.ddns</Name>
         <Url>api/ddns/ddns-list</Url>
      </Function>
   </Passed>
</response>
```
