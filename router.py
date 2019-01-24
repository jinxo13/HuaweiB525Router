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

class xmlobject(object):
    def buildXML(self, header=False):
        result = []
        if (header): result.append('<?xml version:"1.0" encoding="UTF-8"?><request>')
        for property, value in vars(self).iteritems():
            result.extend(['<', property, '>'])
            if (type(value) is list):
                for v in value:
                    if (issubclass(type(v), xmlobject)):
                        result.extend(['<', type(v).__name__, '>'])
                        result.append(v.buildXML())
                        result.extend(['</', type(v).__name__, '>'])
                    else:
                        result.append(v.buildXML())
            elif (issubclass(type(value), xmlobject)):
                result.extend(['<', type(value).__name__, '>'])
                result.append(value.buildXML())
                result.extend(['</', type(value).__name__, '>'])
            else:
                result.append(str(value))
            result.extend(['</', property, '>'])
        if (header): result.append('</request>')
        return ''.join(result)

class macfilter(xmlobject):
    def __init__(self, value):
        self.value=value
        self.status=1

class macfilters(xmlobject):
    MODE_DISABLE=0
    MODE_ALLOW=1
    MODE_DENY=2
    def __init__(self):
        self.policy=self.MODE_DENY
        self.macfilters=[]
    def setAllow(self): self.policy=self.MODE_ALLOW
    def setDeny(self): self.policy=self.MODE_DENY
    def setDisabled(self): self.policy=self.MODE_DISABLE
    def addMac(self, macfilter):
        self.macfilters.append(macfilter)
        return self

class RouterControl(xmlobject):
    REBOOT = 1
    POWEROFF = 4
    def __init__(control):
        self.Control = control

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
        scram_data = ET.fromstring(response.text)
        verification_token = response.headers['__RequestVerificationToken']

        duration = datetime.now() - self.lastLogin
        if (duration.total_seconds() <= self.LOGIN_TIMEOUT):
            logging.warning('Skip login')
            return self.__get_server_token()[32:]

        logging.warning('Do new login')

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
        verification_token = result.headers['__RequestVerificationTokenone']
        self.lastLogin = datetime.now()
        return verification_token

    def __api(self, api_url, data=None):
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
        return response

    #Disabled: <response><macfilters></macfilters><policy>2</policy></response>
    #Allow: <response><macfilters><macfilter><value>b2:27:eb:dd:0d:d2</value><status>1</status></macfilter></macfilters><policy>1</policy></response>
    #Deny: <request><policy>2</policy><macfilters><macfilter><value>b2:27:eb:dd:0d:d2</value><status>1</status></macfilter></macfilters></request>

    ######################## API GET Calls ##############################
    def getInfo(self): return self.__api("api/device/information")
    def getTraffic(self): return self.__api("api/monitoring/traffic-statistics")
    def getStats(self): return self.__api("api/monitoring/month_statistics")
    def getClients(self): return self.__api("api/wlan/host-list")
    def getAllClients(self): return self.__api("api/lan/HostInfo")
    def getSignal(self): return self.__api("api/device/signal")
    def getMACFilter(self): return self.__api("api/security/mac-filter")

    ######################## API POST Calls ##############################
    def doReboot(self):
        control = RouterControl(RouterControl.REBOOT)
        data = control.buildXML(control, True)
        return self.__api("api/device/control", data)

    def doPowerOff(self):
        control = RouterControl(RouterControl.POWEROFF)
        data = control.buildXML(True)
        return self.__api("api/device/control", data)

    def setDenyMacFilter(self, macs):
        filter = macfilters()
        for m in macs:
            filter.addMac(macfilter(m))
        data = filter.buildXML(True)
        return self.__api("api/security/mac-filter", data)

    def clearMacFilter(self):
        #Clearing didn't seem to work as expected. So instead I just deny a single designated test mac
        return self.setDenyMacFilter(['92:1b:46:9d:be:86'])
