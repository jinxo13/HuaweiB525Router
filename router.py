""" Huawei router commands  """
import xml.etree.ElementTree as ET
import sys
from time import sleep
import requests
import logging
from datetime import datetime, timedelta

#Local imports
import xmlobjects
import utils
from errors import RouterError
import crypto

#Dictionary to hold all GET APIS, used by testFeatures function
GET_APIS = {}
#Decorator for GET API functions, populates the GET_APIS dictionary
def getapi(api):
    def api_decorator(f):
        GET_APIS[f.__name__]=api
        def decorated_function(*args, **kwargs):
            inst = args[0]
            if issubclass(type(inst), routerObject):
                return inst.router.api(api)
            else:
                return inst.api(api)
        return decorated_function
    return api_decorator

class routerObject(object):
    def __init__(self, router):
        self.router = router
        self.api = router.api

class Lan(routerObject):
    @getapi(api='dhcp/settings')
    def getLanSettings(self): pass
    @getapi(api='dhcp/static-addr-info')
    def getStaticHosts(self): pass
    @getapi(api='wlan/host-list')
    def getClients(self): pass
    @getapi(api='lan/HostInfo')
    def getAllClients(self): pass
    def setDhcpOff(self):
        '''Turn off routers DHCP function'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDhcpOff()
        data = config.buildXML()
        return self.api('dhcp/settings', data)

    def setDhcpOn(self, startAddress, endAddress, leaseTime=86400):
        '''Turn on routers DHCP function, and set start and end addresses'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDhcpOn(startAddress, endAddress, leaseTime)
        data = config.buildXML()
        return self.api('dhcp/settings', data)

    def setLanAddress(self, ipaddress, netmask='255.255.255.0', url='homerouter.cpe'):
        '''Change the LAN ip address or router name on the LAN'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setLanAddress(ipaddress, netmask, url)
        data = config.buildXML()
        return self.api('dhcp/settings', data)

    def setManualDns(self, primaryDns, secondaryDns=''):
        '''Set manual DNS servers'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDnsManual(primaryDns, secondaryDns)
        data = config.buildXML()
        return self.api('dhcp/settings', data)

    def setAutomaticDns(self):
        '''Use internet host provided DNS servers'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDnsAutomatic()
        data = config.buildXML()
        return self.api('dhcp/settings', data)

    def setAllLanSettings(self, config):
        '''Manually set all lan settings'''
        data = config.buildXML()
        return self.api('dhcp/settings', data)

    def setStaticHosts(self, config):
        '''Set static host IP Addresses'''
        data = config.buildXML()
        return self.api('dhcp/static-addr-info', data)

class User(routerObject):
    @getapi(api='user/history-login')
    def getUserHistory(self): pass

class Device(routerObject):
    @getapi(api='device/information')
    def getInfo(self): pass
    @getapi(api='device/signal')
    def getSignal(self): pass
    @getapi(api='led/circle-switch')
    def getCircleLed(self): pass
    @getapi(api='security/bridgemode')
    def getBridgeMode(self): pass #Returns Not supported error on B525
    def getSignalStrength(self):
        '''Returns a signal strength from 0 to 5 (where 5 is the best), based on the rsrp value'''
        response = self.getSignal()
        root = ET.fromstring(response)
        rsrp = int(root.findall('./rsrp')[0].text[:-3])
        rsrp_q=utils.getRange([-90, -105, -112, -125, -136], rsrp)
        result = xmlobjects.CustomXml({'SignalStrength': 5-rsrp_q})
        return result.buildXML(root='response')

    def doReboot(self):
        '''Reboot the router'''
        control = xmlobjects.RouterControl.reboot()
        data = control.buildXML()
        return self.api('device/control', data)

    def doPowerOff(self):
        '''Power off the router'''
        control = xmlobjects.RouterControl.poweroff()
        data = control.buildXML()
        return self.api('device/control', data)

class Security(routerObject):
    @getapi(api='security/mac-filter')
    def getMacFilter(self): pass
    @getapi(api='timerule/timerule')
    def getTimeRule(self): pass
    def setDenyMacFilter(self, macs):
        '''Block listed MAC addresses LAN/WAN access'''
        filter = xmlobjects.macfilters()
        filter.setDeny()
        for m in macs:
            filter.addMac(xmlobjects.macfilter(m))
        data = filter.buildXML()
        return self.api('security/mac-filter', data)

    def setAllowMacFilter(self, macs):
        '''Allow only listed MAC addresses LAN/WAN access'''
        filter = xmlobjects.macfilters()
        filter.setAllow()
        for m in macs:
            filter.addMac(xmlobjects.macfilter(m))
        data = filter.buildXML()
        return self.api('security/mac-filter', data)

    def setMacFilterOff(self):
        '''Turn off any MAC Deny or Allow filtering'''
        #Disabling didn't seem to work as expected. So instead I just deny a single designated test mac
        return self.setDenyMacFilter(['92:1b:46:9d:be:86'])

class Monitoring(routerObject):
    @getapi(api='monitoring/status')
    def getStatus(self): pass
    @getapi(api='monitoring/traffic-statistics')
    def getTraffic(self): pass
    @getapi(api='monitoring/month_statistics')
    def getStats(self): pass
    @getapi(api='monitoring/check-notifications')
    def getNotifications(self): pass
    def clearTrafficStats(self):
        '''Clear the monthly statictics'''
        config = xmlobjects.CustomXml({'ClearTraffic': 1})
        data = config.buildXML()
        return self.api('monitoring/clear-traffic', data)
    @getapi(api='monitoring/start_date')
    def getTrafficAlert(self): pass
    def setTrafficAlert(self, start_day, data_limit, threshhold):
        '''
        <StartDay>1</StartDay>
        <DataLimit>0MB</DataLimit>
        <DataLimitAwoke>0</DataLimitAwoke>
        <MonthThreshold>90</MonthThreshold>
        <SetMonthData>0</SetMonthData>
        <trafficmaxlimit>0</trafficmaxlimit>
        <turnoffdataenable>0</turnoffdataenable>
        <turnoffdataswitch>0</turnoffdataswitch>
        <turnoffdataflag>0</turnoffdataflag>            
        '''
        xml = xmlobjects.CustomXml({
            'StartDay': start_day,
            'DataLimit': data_limit,
            'MonthThreshold': threshhold,
            'SetMonthData': 1
            })
        data = xml.buildXML()
        self.api('monitoring/start_date', data)

class Wan(routerObject):
    @getapi(api='security/virtual-servers')
    def getVirtualServer(self): pass
    def setVirtualServer(self, servers):
        data = servers.buildXML()
        return self.api('security/virtual-servers', data)
    def clearVirtualServer(self):
        config = xmlobjects.CustomXml({'Servers': ''})
        return self.setVirtualServer(config)


class B525Router(object):
    LOGIN_TIMEOUT=300 #5 minutes

    def __init__(self, router, username, password):
        self.lastLogin=datetime.now()-timedelta(seconds=self.LOGIN_TIMEOUT)
        self.client = None
        self.router = router
        self.username = username
        self.__password = password

        self.device=Device(self)
        self.lan=Lan(self)
        self.user=User(self)
        self.monitoring=Monitoring(self)
        self.wan=Wan(self)
        self.security=Security(self)

    def __setup_session(self):
        """ gets the url from the server ignoring the respone, just to get session cookie set up """
        url = "http://%s/" % self.router
        response = self.client.get(url)
        response.raise_for_status()
        # will have to debug this one as without delay here it was throwing a buffering exception on one of the machines
        sleep(1)

    def __get_server_token(self):
        """ retrieves server token """
        url = "http://%s/api/webserver/token" % self.router
        token_response = self.client.get(url).text
        if (RouterError.hasError(token_response)):
            raise RouterError(token_response)
        root = ET.fromstring(token_response)
        return root.findall('./token')[0].text

    def __login(self):
        """ logs in to the router using SCRAM method of authentication """
        self.__setup_session()
        token = self.__get_server_token()
        url = "http://%s/api/user/challenge_login" % self.router
        request = ET.Element('request')
        username = ET.SubElement(request, 'username')
        username.text = self.username
        clientnonce = crypto.generate_nonce()
        firstnonce = ET.SubElement(request, 'firstnonce')
        firstnonce.text = clientnonce
        mode = ET.SubElement(request, 'mode')
        mode.text = '1'
        headers = {'Content-type': 'text/html',
                '__RequestVerificationToken': token[32:]}
        response = self.client.post(url, data=ET.tostring(
            request, encoding='utf8', method='xml'), headers=headers)
        if (RouterError.hasError(response.text)):
            raise RouterError(response.text)
        scram_data = ET.fromstring(response.text)
        verification_token = response.headers['__RequestVerificationToken']

        duration = datetime.now() - self.lastLogin
        if (duration.total_seconds() <= self.LOGIN_TIMEOUT):
            return self.__get_server_token()[32:]
        servernonce = scram_data.findall('./servernonce')[0].text
        salt = scram_data.findall('./salt')[0].text
        iterations = int(scram_data.findall('./iterations')[0].text)
        login_request = ET.Element('request')
        clientproof = ET.SubElement(login_request, 'clientproof')
        clientproof.text = crypto.get_client_proof(
            clientnonce, servernonce, self.__password, salt, iterations).decode('UTF-8')
        finalnonce = ET.SubElement(login_request, 'finalnonce')
        finalnonce.text = servernonce
        headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                '__RequestVerificationToken': verification_token}

        url = "http://%s/api/user/authentication_login" % self.router
        result = self.client.post(url, data=ET.tostring(
            login_request, encoding='utf8', method='xml'), headers=headers)
        if (RouterError.hasError(result.text)):
            raise RouterError(result.text)
        verification_token = result.headers['__RequestVerificationTokenone']
        self.lastLogin = datetime.now()
        return verification_token

    def api(self, api_url, data=None):
        """ Handles all api calls to the router """
        if (self.client is None):
            self.client = requests.Session()
        verification_token = self.__login()
        url = "http://%s/api/%s" % (self.router, api_url)
        headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            '__RequestVerificationToken': verification_token}
        if (data == None):
            response = self.client.get(url, headers=headers).text
        else:
            response = self.client.post(url, data=data, headers=headers).text

        #Add error message if known and missing
        if RouterError.hasError(response):
            error = xmlobjects.Error()
            error.parseXML(response)
            response = error.buildXML(root='error')
        return response


    def testFeatures(self):
        ''' Tests the routers available features'''
        result = xmlobjects.TestFunctions()
        info = self.device.getInfo()
        if (not RouterError.hasError(info)):
            result.parseXML(info)

        objs = [self]

        for value in vars(self).values():
            if (issubclass(type(value), routerObject)):
                objs.append(value)

        #Iterate through getapi calls
        for f in GET_APIS:
            api = GET_APIS[f]
            func = None
            #find function
            for ob in objs:
                if (hasattr(ob,f)):
                    func = getattr(ob, f)
                    result.addFunction(ob, f, api, func())
            
        return result.buildXML(root='response')

    def logout(self):
        '''Logout user'''
        xml = xmlobjects.CustomXml({'logout': 1})
        data = xml.buildXML()
        return self.api('user/logout', data)
