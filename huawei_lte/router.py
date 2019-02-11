""" Huawei router commands  """
import xml.etree.ElementTree as ET
import sys
from time import sleep
from xml.sax.saxutils import escape
import requests
import logging
from datetime import datetime, timedelta
import threading

#Local imports
import huawei_lte.xmlobjects as xmlobjects
import huawei_lte.utils as utils
from huawei_lte.errors import RouterError
import huawei_lte.crypto as crypto

logger = logging.getLogger(__name__)

#Dictionary to hold all GET APIS, used by testFeatures function
GET_APIS = {}
#Decorator for GET API functions, populates the GET_APIS dictionary
def get_api(api):
    '''Designate function as a GET API call'''
    def api_decorator(f):
        GET_APIS[f.__name__] = api
        def decorated_function(*args):
            try:
                inst = args[0]
                if issubclass(type(inst), RouterObject):
                    return inst.router.api(api)
                return inst.api(api)
            except ValueError as err:
                return xmlobjects.Error.xml_error(f.__name__, escape(err.message))
            except:
                logger.exception('message')
                msg = 'Unexpected error: %s' % sys.exc_info()[0]
                return xmlobjects.Error.xml_error(f.__name__, escape(msg))
        return decorated_function
    return api_decorator

def post_api(f):
    '''Decorator to ensure any errors are returned as an XML response'''
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as err:
            return xmlobjects.Error.xml_error(f.__name__, escape(err.message))
        except:
            logger.exception('message')
            msg = 'Unexpected error: %s' % sys.exc_info()[0]
            return xmlobjects.Error.xml_error(f.__name__, escape(msg))
    return decorated_function


class RouterObject(object):
    '''Parent for all router modules'''
    def __init__(self, router):
        self.router = router
        self.api = router.api
        self.enc_api = router.enc_api

    @classmethod
    def _get_param(cls, vals, key, default=None):
        return utils.get_param(vals, key, default)

class Lan(RouterObject):
    '''LAN module'''
    @property
    @get_api(api='dhcp/settings')
    def settings(self): pass

    @property
    @get_api(api='dhcp/static-addr-info')
    def static_hosts(self): pass

    @property
    @get_api(api='wlan/host-list')
    def clients(self): pass

    @property
    @get_api(api='lan/HostInfo')
    def all_clients(self): pass

    @post_api
    def set_settings(self, config):
        return self.api('dhcp/settings', config)

    @post_api
    def set_dhcp_off(self):
        '''Turn off routers DHCP function'''
        settings = xmlobjects.LanSettings()
        settings.parseXML(self.settings)
        settings.setDhcpOff()
        return self.api('dhcp/settings', settings)

    @post_api
    def set_dhcp(self, config):
        '''
        Turn on routers DHCP function, and set start and end addresses
        {'startAddress': 'xxx', 'endAddress': 'xxx', 'leaseTime': 86400}
        {'startAddress': 'xxx', 'endAddress': 'xxx'}
        '''
        settings = xmlobjects.LanSettings()
        settings.parseXML(self.settings)
        settings.setDhcpOn(config)
        return self.api('dhcp/settings', settings)

    @post_api
    def set_ipaddress(self, config):
        '''
        Change the LAN ip address or router name on the LAN
        {'ipaddress': 'xxx', 'netmask': '255.255.255.0', 'url': 'homerouter.cpe'}
        {'ipaddress': 'xxx'}
        '''
        settings = xmlobjects.LanSettings()
        settings.parseXML(self.settings)
        settings.setLanAddress(config)
        return self.api('dhcp/settings', settings)

    @post_api
    def set_dns(self, config):
        '''
        Set manual DNS servers
        {'primary': 'xxx', 'secondary': 'xxx'}
        {'primary': 'xxx'}
        '''
        settings = xmlobjects.LanSettings()
        settings.parseXML(self.settings)
        settings.setDnsManual(config)
        return self.api('dhcp/settings', settings)

    @post_api
    def set_dns_auto(self):
        '''
        Use internet host provided DNS servers
        '''
        settings = xmlobjects.LanSettings()
        settings.parseXML(self.settings)
        settings.setDnsAutomatic()
        return self.api('dhcp/settings', settings)

    @post_api
    def add_static_host(self, config):
        '''
        Set static host IP Addresses
        {'macaddress': 'xxx', 'ipaddress': 'xxx'}
        [{'macaddress': 'xxx', 'ipaddress': 'xxx'}, {'macaddress': 'xxx', 'ipaddress': 'xxx'}]
        '''
        settings = xmlobjects.StaticHostCollection()
        settings.parseXML(self.static_hosts)
        if isinstance(config, list):
            for host in config:
                settings.addHost(host)
        else:
            settings.addHost(config)
        return self.api('dhcp/static-addr-info', settings)

    @post_api
    def remove_static_host(self, config):
        '''
        Remove a configured static host
        {'macaddress': 'xxx'}
        [{'macaddress': 'xxx'}, {'macaddress': 'xxx'}]
        '''
        settings = xmlobjects.StaticHostCollection()
        settings.parseXML(self.static_hosts)
        if isinstance(config, list):
            for cfg in config:
                settings.removeHost(cfg['macaddress'])
        else:
            settings.removeHost(config['macaddress'])
        return self.api('dhcp/static-addr-info', settings)

    @post_api
    def clear_static_hosts(self):
        '''
        Remove all static host settings
        '''
        return self.api('dhcp/static-addr-info', xmlobjects.StaticHostCollection())


class User(RouterObject):
    '''User module'''
    @property
    @get_api(api='user/history-login')
    def last_login(self): pass

class Device(RouterObject):
    '''Device module'''
    @property
    @get_api(api='device/information')
    def info(self): pass

    @property
    @get_api(api='device/signal')
    def signal(self): pass

    @property
    @get_api(api='monitoring/status')
    def status(self): pass

    @property
    @get_api(api='led/circle-switch')
    def circleled(self): pass

    @property
    @get_api(api='security/bridgemode')
    def bridgemode(self): pass #Returns Not supported error on B525

    @property
    @post_api
    def signal_strength(self):
        '''Returns a signal strength from 0 to 5 (where 5 is the best), based on the rsrp value'''
        response = self.signal
        root = ET.fromstring(response)
        rsrp = int(root.findall('./rsrp')[0].text[:-3])
        rsrp_q=utils.getRange([-90, -105, -112, -125, -136], rsrp)
        result = xmlobjects.CustomXml({'SignalStrength': 5-rsrp_q})
        return result.buildXmlResponse()

    @post_api
    def do_reboot(self):
        '''Reboot the router'''
        control = xmlobjects.RouterControl.reboot()
        data = control.buildXML()
        return self.api('device/control', data)

    @post_api
    def do_poweroff(self):
        '''Power off the router'''
        control = xmlobjects.RouterControl.poweroff()
        data = control.buildXML()
        return self.api('device/control', data)

class Network(RouterObject):
    '''Network module'''
    @property
    @get_api(api='net/net-mode')
    def mode(self):
        pass

    @property
    @get_api(api='net/net-mode-list')
    def modelist(self):
        pass

    @property
    @post_api
    def modelist2(self):
        net = xmlobjects.NetworkMode()
        net.parseXML(self.mode)

        net_bands = []
        for band in xmlobjects.NetworkMode.band_from_hex(net.NetworkBand):
            if (band == 'EXTRA'):
                continue
            net_bands.append(xmlobjects.CustomXml({'Band': band}))

        lte_bands = []
        for band in xmlobjects.NetworkMode.lte_from_hex(net.LTEBand):
            lte_bands.append(xmlobjects.CustomXml({'Band': band}))
        xml = xmlobjects.CustomXml({
            'NetworkMode': xmlobjects.NetworkMode.get_mode(net.NetworkMode),
            'NetworkBands': net_bands,
            'LTEBands': lte_bands
        })
        return xml.buildXmlResponse()

    @post_api
    def set_lte_band(self, config):
        '''
        <NetworkMode>00</NetworkMode>
        <NetworkBand>100200000CE80380</NetworkBand>
        <LTEBand>80080000C5</LTEBand>
        '''
        bands = self._get_param(config, 'bands')
        net = xmlobjects.NetworkMode()
        net.parseXML(self.mode)
        net.set_lte_band(bands)
        return self.api('net/net-mode', net)
    
    @post_api
    def set_network_band(self, config):
        bands = self._get_param(config, 'bands')
        #Fuge to always add the extra unexplained values
        bands.append('EXTRA')
        net = xmlobjects.NetworkMode()
        net.parseXML(self.mode)
        net.set_network_band(bands)
        return self.api('net/net-mode', net)

    @post_api
    def set_network_mode(self, config):
        mode = self._get_param(config, 'mode')
        net = xmlobjects.NetworkMode()
        net.parseXML(self.mode)
        net.set_network_mode(mode)
        return self.api('net/net-mode', net)

class Security(RouterObject):
    '''Security module'''
    @property
    @get_api(api='security/mac-filter')
    def macfilter(self):
        pass

    @get_api(api='timerule/timerule')
    def timerule(self):
        pass

    @post_api
    def deny_macaddress(self, macs):
        '''Block listed MAC addresses LAN/WAN access'''
        fltr = xmlobjects.MacFilterCollection()
        fltr.setDeny()
        for mac in macs:
            fltr.addMac(xmlobjects.MacFilter(mac))
        data = fltr.buildXML()
        return self.api('security/mac-filter', data)

    @post_api
    def allow_macaddress(self, macs):
        '''Allow only listed MAC addresses LAN/WAN access'''
        fltr = xmlobjects.MacFilterCollection()
        fltr.setAllow()
        for mac in macs:
            fltr.addMac(xmlobjects.MacFilter(mac))
        data = fltr.buildXML()
        return self.api('security/mac-filter', data)

    @post_api
    def set_macfilter_off(self):
        '''
        Turn off any MAC Deny or Allow filtering
        Disabling didn't seem to apply immediately.
        So instead just deny a single designated test mac
        '''
        return self.deny_macaddress(['92:1b:46:9d:be:86'])

class Monitoring(RouterObject):
    '''Monitoring module'''
    @property
    @get_api(api='monitoring/traffic-statistics')
    def traffic(self):
        pass

    @property
    @get_api(api='monitoring/month_statistics')
    def stats(self):
        pass

    @property
    @get_api(api='monitoring/check-notifications')
    def notifications(self):
        pass

    @property
    @get_api(api='monitoring/start_date')
    def trafficalert(self):
        pass

    @post_api
    def clear_stats(self):
        '''
        Clear the monthly statictics
        NOTE: The StartDay value in monitoring/start-date will trigger an automatic reset
        of the monthly statistics. For example StartDay=1, on 1st of month at 00:00 the
        monthly statistics will be reset.
        '''
        return self.api('monitoring/clear-traffic', {'ClearTraffic': 1})

    @post_api
    def set_trafficalert(self, config):
        '''
        #TODO: Determine if the following are implementable
        <trafficmaxlimit>0</trafficmaxlimit> #Looks to be dynamically determined based on DataLimit
        <turnoffdataenable>0</turnoffdataenable>
        <turnoffdataswitch>0</turnoffdataswitch>
        <turnoffdataflag>0</turnoffdataflag>
        '''
        startday = self._get_param(config, 'startday', 1)
        datalimit = self._get_param(config, 'datalimit', '0GB')
        threshold = self._get_param(config, 'threshold', 0)
        return self.api(
            'monitoring/start_date',
            {
                'StartDay': startday,
                'DataLimit': datalimit,
                'DataLimitAwoke': 0,
                'MonthThreshold': threshold,
                'SetMonthData': 1
            })

class Wan(RouterObject):
    '''WAN module'''
    @property
    @get_api(api='security/virtual-servers')
    def port_forwards(self): pass

    @post_api
    def add_port_forward(self, config):
        settings = xmlobjects.VirtualServerCollection()
        settings.parseXML(self.port_forwards)
        if not isinstance(config, list):
            config = [config]
        for cfg in config:
            settings.add_service(cfg)
        return self.api('security/virtual-servers', settings)
    
    @post_api
    def clear_port_forwards(self):
        return self.api('security/virtual-servers', {'Servers': ''})

    @post_api
    def remove_port_forward(self, config):
        settings = xmlobjects.VirtualServerCollection()
        settings.parseXML(self.port_forwards)
        if not isinstance(config, list):
            config = [config]
        for cfg in config:
            name = self._get_param(cfg, 'name')
            settings.remove_service(name)
        return self.api('security/virtual-servers', settings)

    @property
    @get_api(api='ddns/ddns-list')
    def ddns(self): pass

    @post_api
    def add_ddns(self, config):
        settings = xmlobjects.DdnsCollection()
        settings.addDdns(config)
        settings.setToAdd()
        return self.enc_api('ddns/ddns-list', settings)

    @post_api
    def edit_ddns(self, config):
        settings = xmlobjects.DdnsCollection()
        settings.setToEdit()
        ddns = settings.addDdns(config)
        xml = ET.fromstring(self.ddns)
        ele = xml.findall('.//ddns[domainname="%s"]' % ddns.domainname)
        if ele is None:
            raise ValueError('Unable to find domain: %s' % ddns.domainname)
        ddns.index = ele[0].find('.//index').text
        return self.enc_api('ddns/ddns-list', settings)

    @post_api
    def remove_ddns(self, config):
        domain = self._get_param(config, 'domain')
        xml = ET.fromstring(self.ddns)
        ele = xml.findall('.//ddns[domainname="%s"]' % domain)
        if ele is None:
            raise ValueError('Unable to find domain: %s' % domain)
        index = ele[0].find('.//index').text
        settings = xmlobjects.DdnsCollection()
        settings.setToDelete()
        settings.ddnss.append(xmlobjects.CustomXml({'index': index}, 'ddns'))
        return self.enc_api('ddns/ddns-list', settings)

class B525Router(object):
    '''B525 implementation'''
    REQUEST_TOKEN = '__RequestVerificationToken'

    def __init__(self, host):
        self.client = None
        self.router = host

        self.username = None
        self.__password = None
        self.__rsae = None
        self.__rsan = None
        self.__is_logged_in = False
        self.__lock = threading.Lock()

        self.device = Device(self)
        self.lan = Lan(self)
        self.user = User(self)
        self.monitoring = Monitoring(self)
        self.wan = Wan(self)
        self.security = Security(self)
        self.net = Network(self)

    def login(self, username, password, keepalive=300):
        with self.__lock:
            self.__last_login=datetime.now()-timedelta(seconds=keepalive)
            self.username = username
            self.__password = password
            self.__timeout = keepalive
            return self.__login()

    def __setup_session(self):
        """ gets the url from the server ignoring the response, just to get session cookie set up """
        if self.client is None:
            self.client = requests.Session()
        url = "http://%s/" % self.router
        response = self.__get(url)
        response.raise_for_status()
        # will have to debug this one as without delay here it was throwing
        # a buffering exception on one of the machines
        sleep(1)

    def __get_server_token(self):
        """ retrieves server token """
        url = "http://%s/api/webserver/token" % self.router
        token_response = self.__get(url).text
        if RouterError.hasError(token_response):
            raise RouterError(token_response)
        root = ET.fromstring(token_response)
        return root.findall('./token')[0].text

    def __api_challenge(self):
        self.__setup_session()
        token = self.__get_server_token()
        url = "http://%s/api/user/challenge_login" % self.router
        self.clientnonce = crypto.generate_nonce()
        xml = xmlobjects.CustomXml({
            'username': self.username,
            'firstnonce': self.clientnonce,
            'mode': 1
            }).buildXML()
        headers = {'Content-type': 'text/html', self.REQUEST_TOKEN: token[32:]}
        response = self.__post(url=url, data=xml, headers=headers)
        if RouterError.hasError(response.text):
            raise RouterError(response.text)
        return response

    def __login(self):
        """ logs in to the router using SCRAM method of authentication """
        logger.info('LOGIN for user [%s]' % self.username)
        response = self.__api_challenge()
        verification_token = response.headers[self.REQUEST_TOKEN]
        scram_data = ET.fromstring(response.text)
        servernonce = scram_data.findall('./servernonce')[0].text
        salt = scram_data.findall('./salt')[0].text
        iterations = int(scram_data.findall('./iterations')[0].text)
        client_proof = crypto.get_client_proof(self.clientnonce, servernonce, self.__password, salt, iterations).decode('UTF-8')
        login_request = xmlobjects.CustomXml({
            'clientproof': client_proof,
            'finalnonce': servernonce}).buildXML()
        headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                   self.REQUEST_TOKEN: verification_token}
        url = "http://%s/api/user/authentication_login" % self.router
        result = self.__post(url=url, data=login_request, headers=headers)
        if RouterError.hasError(result.text):
            raise RouterError(result.text)
        verification_token = result.headers[self.REQUEST_TOKEN]
        self.__last_login = datetime.now()
        '''
        The SCRAM protocol would normally validate the server signatures
        We're assuming this is ok
        e.g.
        var serverProof = scram.serverProof(psd, salt, iter, authMsg);
        if (ret.response.serversignature == serverProof) {
        var publicKeySignature = scram.signature(CryptoJS.enc.Hex.parse(ret.response.rsan), CryptoJS.enc.Hex.parse(serverKey)).toString();
        if (ret.response.rsapubkeysignature == publicKeySignature) {
        '''
        xml = ET.fromstring(result.text)
        self.__rsae = xml.find('.//rsae').text
        self.__rsan = xml.find('.//rsan').text
        self.__is_logged_in = True

    def enc_api(self, url, data):
        return self.api(url=url, data=data, encrypted=True)

    def __post(self, url, data, headers):
        logger.debug('------------ REQUEST to %s -------------', url)
        logger.debug('-- HEADERS --')
        logger.debug('%s', headers)
        logger.debug('-------------')
        logger.debug('-- DATA --')
        logger.debug('%s', data)
        logger.debug('-------------')
        result = self.client.post(url, data=data, headers=headers)
        logger.info('POST %s %i' % (url, result.status_code))
        logger.debug('------------ RESPONSE to %s -------------', url)
        logger.debug('-- HEADERS --')
        logger.debug('%s', result.headers)
        logger.debug('-------------')
        logger.debug('-- DATA --')
        logger.debug('%s', result.text)
        logger.debug('-------------')
        return result

    def __get(self, url, headers=None):
        logger.debug('------------ REQUEST to %s -------------', url)
        logger.debug('-- HEADERS --')
        logger.debug('%s', headers)
        logger.debug('-------------')
        result = self.client.get(url, headers=headers)
        logger.info('GET %s %i' % (url, result.status_code))
        logger.debug('------------ RESPONSE to %s -------------', url)
        logger.debug('-- HEADERS --')
        logger.debug('%s', result.headers)
        logger.debug('-------------')
        logger.debug('-- DATA --')
        logger.debug('%s', result.text)
        logger.debug('-------------')
        return result
        
    @post_api
    def api(self, url, data=None, encrypted=False):
        """ Handles all api calls to the router """
        #Check if the session has timed out, and login again if it has
        timed_out = datetime.now() - self.__last_login
        if (timed_out.total_seconds() >= self.__timeout and self.__is_logged_in):
            with self.__lock:
                if (timed_out.total_seconds() >= self.__timeout and self.__is_logged_in):
                    logger.debug('Session timeout - establishing new login...')
                    self.__login()
        verification_token = self.__get_server_token()[32:]

        if isinstance(data, dict):
            data = xmlobjects.CustomXml(data).buildXML()
        elif isinstance(data, xmlobjects.XmlObject):
            data = data.buildXML()

        url = "http://%s/api/%s" % (self.router, url)
        headers = {}
        headers[self.REQUEST_TOKEN] = verification_token
        if (encrypted):
            headers['Content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8;enc'
        else:
            headers['Content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        if data is None or data == '':
            response = self.__get(url, headers).text
        else:
            if encrypted:
                data = crypto.rsa_encrypt(self.__rsae, self.__rsan, data)
            response = self.__post(url, data, headers).text    

        #Add error message if known and missing
        if RouterError.hasError(response):
            error = xmlobjects.Error()
            error.parseXML(response)
            response = error.buildXmlError()
        return response


    @property
    def features(self):
        ''' Tests the routers available features'''
        result = xmlobjects.TestFunctions()
        info = self.device.info
        if (not RouterError.hasError(info)):
            result.parseXML(info)

        objs = [self]

        for value in vars(self).values():
            if issubclass(type(value), RouterObject):
                objs.append(value)

        #Iterate through get_api calls
        for f in GET_APIS:
            api = GET_APIS[f]
            func = None
            #find function
            for ob in objs:
                if hasattr(ob,f):
                    if isinstance(getattr(type(ob), f, None), property):
                        prop = getattr(type(ob), f, None)
                        result.addFunction(ob, f, api, prop.__get__(ob, type(ob)))
                    else:
                        func = getattr(ob, f)
                        result.addFunction(ob, f, api, func())
            
        return result.buildXmlResponse()

    @post_api
    def logout(self):
        '''Logout user'''
        with self.__lock:
            logger.info('LOGOUT for user [%s]', self.username)
            response = self.api('user/logout', {'Logout': 1})
            if RouterError.hasError(response):
                raise RouterError(response)
            self.__is_logged_in = False
