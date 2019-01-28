""" Huawei router commands  """
import xml.etree.ElementTree as ET
import sys
import uuid
import hashlib
import hmac
from time import sleep
from binascii import hexlify
import requests
import logging
from datetime import datetime, timedelta

#Local imports
import xmlobjects
import utils
from errors import RouterError

#Dictionary to hold all GET APIS, used by testFeatures function
GET_APIS = {}
#Decorator for GET API functions, populates the GET_APIS dictionary
def getapi(api):
    def api_decorator(f):
        GET_APIS[f.__name__]=api
        def decorated_function(*args, **kwargs):
            inst = args[0]
            return inst.api(api)
        return decorated_function
    return api_decorator

class B525Router(object):
    LOGIN_TIMEOUT=300 #5 minutes

    @classmethod
    def __generate_nonce(cls):
        """ generate random clientside nonce """
        return uuid.uuid4().hex + uuid.uuid4().hex

    @classmethod
    def __get_client_proof(cls, clientnonce, servernonce, password, salt, iterations):
        """ calculates server client proof (part of the SCRAM algorithm) """
        msg = "%s,%s,%s" % (clientnonce, servernonce, servernonce)
        salted_pass = hashlib.pbkdf2_hmac(
            'sha256', password, bytearray.fromhex(salt), iterations)
        client_key = hmac.new(b'Client Key', msg=salted_pass,
                            digestmod=hashlib.sha256)
        stored_key = hashlib.sha256()
        stored_key.update(client_key.digest())
        signature = hmac.new(msg.encode('utf_8'),
                            msg=stored_key.digest(), digestmod=hashlib.sha256)
        client_key_digest = client_key.digest()
        signature_digest = signature.digest()
        client_proof = bytearray()
        i = 0
        while i < client_key.digest_size:
            client_proof.append(ord(client_key_digest[i]) ^ ord(signature_digest[i]))
            i = i + 1
        return hexlify(client_proof)

    def __init__(self, router, username, password):
        self.lastLogin=datetime.now()-timedelta(seconds=self.LOGIN_TIMEOUT)
        self.client = None
        self.router = router
        self.username = username
        self.password = password

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
        clientnonce = self.__generate_nonce()
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
        clientproof.text = self.__get_client_proof(
            clientnonce, servernonce, self.password, salt, iterations).decode('UTF-8')
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
        else:
            logging.warning('Using same session')
        verification_token = self.__login()
        url = "http://%s/%s" % (self.router, api_url)
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

    ######################## API GET Calls ##############################
    @getapi(api='api/user/history-login')
    def getUserHistory(self): pass

    @getapi(api='api/device/information')
    def getInfo(self): pass
    
    @getapi(api='api/monitoring/traffic-statistics')
    def getTraffic(self, api=''): pass

    @getapi(api='api/monitoring/month_statistics')
    def getStats(self): pass

    @getapi(api='api/wlan/host-list')
    def getClients(self): pass

    @getapi(api='api/lan/HostInfo')
    def getAllClients(self): pass

    @getapi(api='api/device/signal')
    def getSignal(self): pass

    @getapi(api='api/security/mac-filter')
    def getMacFilter(self): pass

    @getapi(api='api/dhcp/settings')
    def getLanSettings(self): pass

    @getapi(api='api/dhcp/static-addr-info')
    def getStaticHosts(self): pass

    @getapi(api='api/security/bridgemode')
    def getBridgeMode(self): pass #Returns Not supported error on B525

    @getapi(api='api/timerule/timerule')
    def getTimeRule(self): pass

    @getapi(api='api/led/circle-switch')
    def getCircleLed(self): pass

    def testFeatures(self):
        ''' Tests the routers available features'''
        result = xmlobjects.TestFunctions()
        info = self.getInfo()
        if (not RouterError.hasError(info)):
            result.parseXML(info)

        #Iterate through getapi calls
        for f in GET_APIS:
            func = getattr(self, f)
            api = GET_APIS[f]
            result.addFunction(f, api, func())
            
        return result.buildXML(root='response')

    ######################## API Custom GET Calls ##############################
    def getSignalStrength(self):
        '''Returns a signal strength from 0 to 5 (where 5 is the best), based on the rsrp value'''
        response = self.getSignal()
        root = ET.fromstring(response)
        rsrp = int(root.findall('./rsrp')[0].text[:-3])
        rsrp_q=utils.getRange([-90, -105, -112, -125, -136], rsrp)
        result = xmlobjects.CustomXml({'SignalStrength': 5-rsrp_q})
        return result.buildXML(root='response')

    ######################## API POST Calls ##############################
    def logout(self):
        '''Logout user'''
        xml = xmlobjects.CustomXml({'logout': 1})
        data = xml.buildXML()
        return self.api('api/user/logout', data)

    def doReboot(self):
        '''Reboot the router'''
        control = xmlobjects.RouterControl.reboot()
        data = control.buildXML()
        return self.api('api/device/control', data)

    def doPowerOff(self):
        '''Power off the router'''
        control = xmlobjects.RouterControl.poweroff()
        data = control.buildXML()
        return self.api('api/device/control', data)

    def setDenyMacFilter(self, macs):
        '''Block listed MAC addresses LAN/WAN access'''
        filter = xmlobjects.macfilters()
        filter.setDeny()
        for m in macs:
            filter.addMac(xmlobjects.macfilter(m))
        data = filter.buildXML()
        return self.api('api/security/mac-filter', data)

    def setAllowMacFilter(self, macs):
        '''Allow only listed MAC addresses LAN/WAN access'''
        filter = xmlobjects.macfilters()
        filter.setAllow()
        for m in macs:
            filter.addMac(xmlobjects.macfilter(m))
        data = filter.buildXML()
        return self.api('api/security/mac-filter', data)

    def setMacFilterOff(self):
        '''Turn off any MAC Deny or Allow filtering'''
        #Disabling didn't seem to work as expected. So instead I just deny a single designated test mac
        return self.setDenyMacFilter(['92:1b:46:9d:be:86'])

    def setDhcpOff(self):
        '''Turn off routers DHCP function'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDhcpOff()
        data = config.buildXML()
        return self.api('api/dhcp/settings', data)

    def setDhcpOn(self, startAddress, endAddress, leaseTime=86400):
        '''Turn on routers DHCP function, and set start and end addresses'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDhcpOn(startAddress, endAddress, leaseTime)
        data = config.buildXML()
        return self.api('api/dhcp/settings', data)

    def setLanAddress(self, ipaddress, netmask='255.255.255.0', url='homerouter.cpe'):
        '''Change the LAN ip address or router name on the LAN'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setLanAddress(ipaddress, netmask, url)
        data = config.buildXML()
        return self.api('api/dhcp/settings', data)

    def setManualDns(self, primaryDns, secondaryDns=''):
        '''Set manual DNS servers'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDnsManual(primaryDns, secondaryDns)
        data = config.buildXML()
        return self.api('api/dhcp/settings', data)

    def setAutomaticDns(self):
        '''Use internet host provided DNS servers'''
        config = xmlobjects.LanSettings()
        config.parseXML(self.getLanSettings())
        config.setDnsAutomatic()
        data = config.buildXML()
        return self.api('api/dhcp/settings', data)

    def setAllLanSettings(self, config):
        '''Manually set all lan settings'''
        data = config.buildXML()
        return self.api('api/dhcp/settings', data)

    def setStaticHosts(self, config):
        '''Set static host IP Addresses'''
        data = config.buildXML()
        return self.api('api/dhcp/static-addr-info', data)

    def clearTrafficStats(self):
        '''Clear the monthly statictics'''
        config = xmlobjects.CustomXml({'ClearTraffic': 1})
        data = config.buildXML()
        return self.api('api/monitoring/clear-traffic', data)
