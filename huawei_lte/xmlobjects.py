import xml.etree.ElementTree as ET
import inspect

import huawei_lte.utils as utils
from huawei_lte.errors import RouterError

class XmlObject(object):
    '''A simple object to handle XML object serialisation'''

    def __init__(self, settings=None):
        self._SKIP_BLANK = self._get_param(settings, 'skip_blanks', False)
        self._SKIP_CLASS_ELEMENT = self._get_param(settings, 'skip_class_element', False)

    @classmethod
    def _get_param(cls, vals, key, default=None):
        return utils.get_param(vals, key, default)

    def getPropertyNames(self):
        result = []
        for prop in vars(self).keys():
            result.append(prop)
        return result

    def getValue(self, prop):
        return getattr(self, prop)

    def getElementName(self):
        return self.__class__.__name__

    def buildXmlRequest(self): return self.buildXML(root='request')
    def buildXmlResponse(self): return self.buildXML(root='response')
    def buildXmlError(self): return self.buildXML(root='error')
    def buildXML(self, header=True, root='request'):
        result = []
        if (header):
            result.append('<?xml version="1.0" encoding="UTF-8"?>')
            result.append('<'+root+'>')
        for prop in self.getPropertyNames():
            value = self.getValue(prop)
            skip_blank = self._SKIP_BLANK and (value is None or value == '')
            if skip_blank or prop[:1] == '_':
                continue
            result.extend(['<', prop, '>'])
            if (type(value) is list):
                for v in value:
                    if (issubclass(type(v), XmlObject)):
                        if not self._SKIP_CLASS_ELEMENT:
                            result.extend(['<', v.getElementName(), '>'])
                        result.append(v.buildXML(False))
                        if not self._SKIP_CLASS_ELEMENT:
                            result.extend(['</', v.getElementName(), '>'])
                    else:
                        result.append(v.buildXML(False))
            elif (issubclass(type(value), XmlObject)):
                result.extend(['<', v.getElementName(), '>'])
                result.append(value.buildXML(False))
                result.extend(['</', v.getElementName(), '>'])
            else:
                result.append(str(value))
            result.extend(['</', prop, '>'])
        if (header):
            result.append('</'+root+'>')
        return ''.join(result)

    def child(self, name, xml):
        return None

    def parseXML(self, xmlText):
        xml = ET.fromstring(xmlText)
        for prop in self.getPropertyNames():
            value = self.getValue(prop)
            if isinstance(value, list):
                parent = xml.find('./'+prop)
                if (parent is not None):
                    for elm in parent.getchildren():
                        xml = ET.tostring(elm, encoding='utf8', method='xml')
                        child = self.child(prop, xml)
                        value.append(child)
            elif (issubclass(type(value), XmlObject)):
                elm = xml.find('./'+prop)
                if (elm is not None):
                    cls = type(value)
                    setattr(self, prop, cls(xml))
            else:
                elm = xml.find('./'+prop)
                if (elm is not None):
                    val = elm.text
                    if (val is None):
                        val = ''
                    setattr(self, prop, val)

class Error(XmlObject):
    PYTHON_API_ERROR_CODE=2000

    def __init__(self, code=0, msg=''):
        super(Error, self).__init__()
        self.code = code
        self.message = msg

    @classmethod
    def xml_error(cls, caller, err):
        code = cls.PYTHON_API_ERROR_CODE
        msg = RouterError.getErrorMessage(code)
        error = Error(code, msg % (caller, err))
        return error.buildXmlError()

    def parseXML(self, xmlText):
        super(Error, self).parseXML(xmlText)
        if (self.message == ''):
            #lookup error message
            self.message = RouterError.getErrorMessage(self.code)
            
class Function(XmlObject):
    def __init__(self, typ, name, url):
        super(Function, self).__init__({'skip_blanks': True})
        self.Name = '%s.%s' % (typ.lower(), name)
        self.Url = 'api/%s' % url
        self.Error = ''

    def getPropertyNames(self):
        return ['Name','Url','Error']

class TestFunctions(XmlObject):
    def __init__(self):
        super(TestFunctions, self).__init__()
        self.DeviceName = ''
        self.ProductFamily = ''
        self.HardwareVersion = ''
        self.SoftwareVersion = ''
        self.WebUIVersion = ''
        self.MacAddress1 = ''
        self.MacAddress2 = ''
        self.Passed = []
        self.Failed = []

    def getPropertyNames(self):
        return ['DeviceName','ProductFamily','HardwareVersion','SoftwareVersion','WebUIVersion','MacAddress1','MacAddress2','Failed','Passed']

    def addFunction(self, obj, name, url, response):
        func = Function(obj.__class__.__name__, name, url)
        if (RouterError.hasError(response)):
            error = Error()
            error.parseXML(response)
            func.Error = error.code + ": " + error.message
            self.Failed.append(func)
        else:
            self.Passed.append(func)

class VirtualServerCollection(XmlObject):
    def __init__(self):
        super(VirtualServerCollection, self).__init__()
        self.Servers = []

    def child(self, name, xml):
        if name == 'Servers':
            return VirtualServer(xml)
        return None

    def add_service(self, config):
        self.Servers.append(VirtualServer(config))

    def remove_service(self, name):
        found = False
        for server in self.Servers:
            if server.VirtualServerIPName == name:
                self.Servers.remove(server)
                found = True
                break
        if not found:
            raise ValueError('No existing port forward named [%s] was found' % name)

    def add_udp_service(self, config):
        config['protocol'] = 'UDP'
        self.add_service(config)

    def add_tcp_service(self, config):
        config['protocol'] = 'TCP'
        self.add_service(config)

class VirtualServer(XmlObject):
    PROTOCOLS = {'UDP': 17, 'TCP': 6, 'BOTH': 0}
    def __init__(self, config):
        #Define properties first to support XML serialisation
        super(VirtualServer, self).__init__()
        self.VirtualServerIPName = ''
        self.VirtualServerStatus = 1
        self.VirtualServerRemoteIP = ''
        self.VirtualServerWanPort = 0
        self.VirtualServerWanEndPort = 0
        self.VirtualServerLanPort = 0
        self.VirtualServerLanEndPort = 0
        self.VirtualServerIPAddress = ''
        self.VirtualServerProtocol = ''

        if isinstance(config, basestring):
            self.parseXML(config)
        else:
            name = self._get_param(config, 'name')
            startWanPort = self._get_param(config, 'startwanport')
            endWanPort = self._get_param(config, 'endwanport', startWanPort)
            startLanPort = self._get_param(config, 'startlanport')
            endLanPort = self._get_param(config, 'endlanport', startLanPort)
            localIp = self._get_param(config, 'localip')
            protocol = self._get_param(config, 'protocol', 'BOTH')
            if protocol not in self.PROTOCOLS:
                raise ValueError('Invalid protocol specified for port forwarding (Virtual Server). Must be one of: [%s]' % ', '.join(self.PROTOCOLS.keys))
            protocol = self.PROTOCOLS[protocol]
            if not utils.isIpValid(localIp):
                raise ValueError('Invalid ipaddress specified for port fowarding target server')
            self.VirtualServerIPName = name
            self.VirtualServerWanPort = startWanPort
            self.VirtualServerWanEndPort = endWanPort
            self.VirtualServerLanPort = startLanPort
            self.VirtualServerLanEndPort = endLanPort
            self.VirtualServerIPAddress = localIp
            self.VirtualServerProtocol = protocol

    def getElementName(self):
        return 'Server'

class NetworkMode(XmlObject):
    NET_MODES = {
        'AUTO': '00',
        '2G': '01', #GSM/GPRS/EDGE 850/900/1800/1900MHz
        '3G': '02', #DC-HSPA+/HSPA+/UMTS Band 1/2/5/6/8/19
        '4G': '03'} #Band 1/3/4/5/7/8/20/19/26/28/32/38/40/41

    NET_BANDS = {
        #2G Bands
        'GSM1800':          '0x80',
        'GSM900':          '0x300',
        'GSM850':        '0x80000',
        'GSM1900':      '0x200000',
        #3G Bands
        'W2100':        '0x400000',
        'W1900':        '0x800000',
        'W850':        '0x4000000',
        'W900':  '0x2000000000000',
        'W1700': '0x4000000000000',
        #Unexplained values
        'EXTRA': '0x1000000008000000'
    }

    LTE_BANDS = {
        #Hex determined from integer 2 ** (bandnum-1)
        'B1': 'FDD 2100 Mhz',
        'B2': 'FDD 1900 Mhz',
        'B3': 'FDD 1800 Mhz',
        'B4': 'FDD 1700 Mhz',
        'B5': 'FDD 850 Mhz',
        'B6': 'FDD 800 Mhz',
        'B7': 'FDD 2600 Mhz',
        'B8': 'FDD 900 Mhz',
        'B19': 'FDD 850 Mhz',
        'B20': 'FDD 800 Mhz',
        'B26': 'FDD 850 Mhz',
        'B28': 'FDD 700 Mhz',
        'B32': 'FDD 1500 Mhz',
        'B38': 'TDD 2600 Mhz',
        'B40': 'TDD 2300 Mhz',
        'B41': 'TDD 2500 Mhz'}

    @classmethod
    def get_mode(cls, mode):
        '''
        Returns the matching mode key
        '''
        for key, val in cls.NET_MODES.items():
            if val == mode:
                return key
        raise ValueError('No matching firendly mode name found for [%s]' % mode)

    @classmethod
    def lte_to_hex(cls, bands):
        '''
        Returns bands as hex
        '''
        result = 0
        for band in bands:
            result += 2 ** (int(band[1:]) - 1)
        return hex(result)

    @classmethod
    def lte_from_hex(cls, hexnum):
        '''
        Returns list of bands from provided hex
        '''
        result = []
        for band in cls.LTE_BANDS.keys():
            bint = 2 ** (int(band[1:]) - 1)
            if int(hexnum,16) & bint == bint:
                result.append(band)
        return result

    @classmethod
    def band_to_hex(cls, bands):
        '''
        Returns bands as hex
        '''
        result = 0
        for band in bands:
            result += int(cls.NET_BANDS[band], 16)
        return hex(result)

    @classmethod
    def band_from_hex(cls, hexnum):
        '''
        Returns list of bands from provided hex
        '''
        result = []
        for band, val in cls.NET_BANDS.items():
            bint = int(val, 16)
            if int(hexnum, 16) & bint == bint:
                result.append(band)
        return result

    def __init__(self):
        '''
        <NetworkMode>00</NetworkMode>
        <NetworkBand>100200000CE80380</NetworkBand>
        <LTEBand>80080000C5</LTEBand>        
        '''
        super(NetworkMode, self).__init__()
        self.NetworkMode = '00' #Automatic
        self.NetworkBand = ''
        self.LTEBand = ''

    @classmethod
    def __clean_hex(cls, hexnum):
        return hexnum.replace('0x','').replace('L','').upper()

    def set_lte_band(self, bands):
        for band in bands:
            if band not in self.LTE_BANDS.keys():
                raise ValueError('Band [%s] is not a known LTE band. Expected format is B1, B2 etc...' % band)
        hexnum = self.lte_to_hex(bands)
        self.LTEBand = self.__clean_hex(hexnum)

    def set_network_band(self, bands):
        for band in bands:
            if band not in self.NET_BANDS.keys():
                raise ValueError('Band [%s] is not a known 2G/3G band. Expected format is GSM800, W1900, etc...' % band)
        hexnum = self.band_to_hex(bands)
        self.NetworkBand = self.__clean_hex(hexnum)

    def set_network_mode(self, mode):
        if mode not in self.NET_MODES.keys():
            raise ValueError('Mode [%s] is not a known mode. Expected one of: %s' % (mode, self.NET_MODES.keys()))
        self.NetworkMode = self.NET_MODES[mode]

class LanSettings(XmlObject):
    def __init__(self):
        super(LanSettings, self).__init__()
        self.DhcpLanNetmask = '255.255.255.0'
        self.homeurl = 'homerouter.cpe'
        self.DnsStatus = 1
        self.PrimaryDns = '192.168.8.1'
        self.SecondaryDns = '192.168.8.1'
        self.accessipaddress = ''
        self.DhcpStatus = 1
        self.DhcpIPAddress = '192.168.8.1' #LAN IP Address
        self.DhcpStartIPAddress = '192.168.8.100'
        self.DhcpEndIPAddress = '192.168.8.200'
        self.DhcpLeaseTime = 86400
    
    def setDnsManual(self, config):
        primaryDns = self._get_param(config, 'primary')
        secondaryDns = self._get_param(config, 'secondary', '')
        if (not utils.isIpValid(primaryDns)): raise ValueError("Invalid Primary DNS IP Address: %s" % primaryDns)
        if (secondaryDns != '' and not utils.isIpValid(secondaryDns)): raise ValueError("Invalid Secondary DNS IP Address: %s" % secondaryDns)
        self.DnsStatus = 0
        self.PrimaryDns = primaryDns
        self.SecondaryDns = secondaryDns
    
    def setDnsAutomatic(self):
        self.DnsStatus = 1
    
    def setLanAddress(self, config):
        ipaddress = self._get_param(config, 'ipaddress')
        self.netmask =  self._get_param(config, 'ipaddress', '255.255.255.0')
        url = self._get_param(config, 'url', 'homerouter.cpe')
        if (not utils.isIpValid(ipaddress)): raise ValueError("Invalid LAN IP Address: %s" % ipaddress)
        self.DhcpIPAddress = ipaddress
        self.homeurl = url

    def setDhcpOn(self, config):
        startAddress = self._get_param(config, 'startaddress')
        endAddress = self._get_param(config, 'endaddress')
        leaseTime = self._get_param(config, 'leasetime', 86400)
        if not utils.isIpValid(startAddress):
            raise ValueError("Invalid DHCP starting IP Address: %s" % startAddress)
        if not utils.isIpValid(endAddress):
            raise ValueError("Invalid DHCP ending IP Address: %s" % endAddress)
        self.DhcpStatus = 1
        self.DhcpStartIPAddress = startAddress
        self.DhcpEndIPAddress = endAddress
        self.DhcpLeaseTime = leaseTime
    def setDhcpOff(self):
        self.DhcpStatus = 0

class MacFilter(XmlObject):
    def __init__(self, value):
        super(MacFilter, self).__init__()
        if not utils.isMacValid(value):
            raise ValueError("Invalid MAC Address to filter: %s" % value)
        self.value=value
        self.status=1
    
    def getElementName(self):
        return self.__class__.__name__.lower()

class MacFilterCollection(XmlObject):
    MODE_DISABLE=0
    MODE_ALLOW=1
    MODE_DENY=2
    def __init__(self):
        super(MacFilterCollection, self).__init__()
        self.policy=self.MODE_DENY
        self.macfilters=[]
    def setAllow(self): self.policy=self.MODE_ALLOW
    def setDeny(self): self.policy=self.MODE_DENY
    def setDisabled(self): self.policy=self.MODE_DISABLE
    def addMac(self, macfilter):
        self.macfilters.append(macfilter)

class StaticHostCollection(XmlObject):
    def __init__(self):
        super(StaticHostCollection, self).__init__()
        self.Hosts = []
    
    def hasHost(self, mac):
        for host in self.Hosts:
            if host.HostHw == mac:
                return True
        return False

    def addHost(self, config):
        host = StaticHost(config)
        if self.hasHost(host.HostHw):
            raise ValueError('The MAC Address to add [%s] is already a static host' % host.HostHw)
        host.HostIndex = len(self.Hosts)+1
        self.Hosts.append(host)

    def removeHost(self, mac):
        found = False
        for host in self.Hosts:
            if host.HostHw == mac:
                self.Hosts.remove(host)
                found = True
                break
        if not found:
            raise ValueError('The MAC Address to remove [%s] is not a current static host' % mac)
        #Reindex
        for i in range(len(self.Hosts)):
            self.Hosts[i].HostIndex = i+1

    def getElementName(self):
        return 'Hosts'

    def child(self, name, xml):
        if name == self.getElementName():
            return StaticHost(xml)
        else:
            return None

class StaticHost(XmlObject):
    def __init__(self, config):
        super(StaticHost, self).__init__()
        self.HostIndex = 0
        self.HostHw = ''
        self.HostIp = ''
        self.HostEnabled = 1
        if isinstance(config, basestring):
            self.parseXML(config)
        else:
            mac = self._get_param(config, 'macaddress')
            ip = self._get_param(config, 'ipaddress')
            if (not utils.isMacValid(mac)): raise ValueError("Invalid static host MAC address: %s" % mac)
            if (not utils.isIpValid(ip)): raise ValueError("Invalid static host IP Address: %s" % ip)
            self.HostHw = mac
            self.HostIp = ip
    
    def getElementName(self):
        return 'Host'

class CustomXml(XmlObject):
    def __init__(self, props, element_name=None):
        super(CustomXml, self).__init__({'skip_class_element': True})
        if element_name is None:
            element_name = self.__class__.__name__
        self.ele_name = element_name
        self.vals = props.copy()
    def getPropertyNames(self):
        return self.vals.keys()
    def getValue(self, property):
        return self.vals[property]
    def getElementName(self): return self.ele_name

class RouterControl(XmlObject):
    NONE = -1
    REBOOT = 1
    POWEROFF = 4
    def __init__(self, control):
        super(RouterControl, self).__init__()
        self.Control = control
    
    @classmethod
    def reboot(cls): return RouterControl(cls.REBOOT)

    @classmethod
    def poweroff(cls): return RouterControl(cls.POWEROFF)

class Ddns(XmlObject):
    PROVIDERS = ["DynDNS.org", "No-IP.com", "oray"]
    def __init__(self, config):
        super(Ddns, self).__init__()
        provider = self._get_param(config, 'provider')
        if (not provider in self.PROVIDERS):
            raise ValueError('Invalid DDNS service provided, it must be one of: [%s]' % ', '.join(self.PROVIDERS))
        self.provider = provider
        self.username = self._get_param(config, 'username')
        self.password = self._get_param(config, 'password')
        self.domainname = self._get_param(config, 'domain')
        self.status = 1
        self.index = 0

    def getElementName(self):
        return self.__class__.__name__.lower()

class DdnsCollection(XmlObject):
    OPERATE_ADD = 1
    OPERATE_DELETE = 2
    OPERATE_EDIT = 3
    def __init__(self):
        super(DdnsCollection, self).__init__()
        self.ddnss = []
        self.operate = self.OPERATE_ADD
    def addNoIpDdns(self, config):
        config['provider'] = Ddns.PROVIDERS[1]
        return self.addDdns(config)

    def addDynDnsDdns(self, config):
        config['provider'] = Ddns.PROVIDERS[0]
        return self.addDdns(config)

    def addOrayDdns(self, config):
        config['provider'] = Ddns.PROVIDERS[2]
        return self.addDdns(config)

    def addDdns(self, config):
        rec = Ddns(config)
        rec.index = len(self.ddnss)
        self.ddnss.append(rec)
        return rec

    def setToAdd(self):
        self.operate = self.OPERATE_ADD

    def setToDelete(self):
        self.operate = self.OPERATE_DELETE

    def setToEdit(self):
        self.operate = self.OPERATE_EDIT
