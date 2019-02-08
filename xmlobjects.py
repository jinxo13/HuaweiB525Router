import xml.etree.ElementTree as ET
import utils
from errors import RouterError

class xmlobject(object):

    def getPropertyNames(self):
        result = []
        for property in vars(self).keys():
            result.append(property)
        return result

    def getValue(self, property):
        return getattr(self, property)

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
        for property in self.getPropertyNames():
            value = self.getValue(property)
            result.extend(['<', property, '>'])
            if (type(value) is list):
                for v in value:
                    if (issubclass(type(v), xmlobject)):
                        result.extend(['<', v.getElementName(), '>'])
                        result.append(v.buildXML(False))
                        result.extend(['</', v.getElementName(), '>'])
                    else:
                        result.append(v.buildXML(False))
            elif (issubclass(type(value), xmlobject)):
                result.extend(['<', v.getElementName(), '>'])
                result.append(value.buildXML(False))
                result.extend(['</', v.getElementName(), '>'])
            else:
                result.append(str(value))
            result.extend(['</', property, '>'])
        if (header):
            result.append('</'+root+'>')
        return ''.join(result)

    def parseXML(self, xmlText):
        xml = ET.fromstring(xmlText)
        for property in self.getPropertyNames():
            value = self.getValue(property)
            if (type(value) is list):
                pass #TODO - support lists
            elif (issubclass(type(value), xmlobject)):
                pass #TODO - support subclasses
            else:
                elm = xml.find('.//'+property)
                if (elm is not None):
                    val = elm.text
                    if (val is None): val = ''
                    setattr(self, property, val)

class Error(xmlobject):
    PYTHON_API_ERROR_CODE=2000

    def __init__(self, code=0, msg=''):
        self.code = code
        self.message = msg

    @classmethod
    def customError(cls, call, err):
        code = cls.PYTHON_API_ERROR_CODE
        msg = RouterError.getErrorMessage(code)
        error = Error(code, msg % (call, err))
        return error

    def parseXML(self, xmlText):
        super(Error, self).parseXML(xmlText)
        if (self.message == ''):
            #lookup error message
            self.message = RouterError.getErrorMessage(self.code)
            
class Function(xmlobject):
    def __init__(self, typ, name, url):
        self.Type = typ
        self.Name = name
        self.Url = url
        self.Error = ''
    def getPropertyNames(self):
        return ['Type','Name','Url','Error']

class TestFunctions(xmlobject):
    def __init__(self):
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

class VirtualServers(xmlobject):
    PROTOCOL_BOTH = 0
    PROTOCOL_TCP = 6
    PROTOCOL_UDP = 17
    def __init__(self):
        self.Servers = []
    def addService(self, name, wanPort, lanPort, localIp, protocol=PROTOCOL_BOTH):
        return self.addServices(name, wanPort, wanPort, lanPort, lanPort, localIp, protocol)
    def addServices(self, name, startWanPort, endWanPort, startLanPort, endLanPort, localIp, protocol=PROTOCOL_BOTH):
        server = Server(name, startWanPort, endWanPort, startLanPort, endLanPort, localIp, protocol)
        self.Servers.append(server)
        return server
    def addUdpService(self, name, wanPort, lanPort, localIp): return self.addService(name, wanPort, lanPort, localIp, self.PROTOCOL_UDP)
    def addTcpService(self, name, wanPort, lanPort, localIp): return self.addService(name, wanPort, lanPort, localIp, self.PROTOCOL_TCP)
    def addBothService(self, name, wanPort, lanPort, localIp): return self.addService(name, wanPort, lanPort, localIp, self.PROTOCOL_BOTH)
    def addUdpServices(self, name, startWanPort, endWanPort, startLanPort, endLanPort, localIp):
        return self.addServices(name, startWanPort, endWanPort, startLanPort, endLanPort, localIp, self.PROTOCOL_UDP)
    def addTcpServices(self, name, startWanPort, endWanPort, startLanPort, endLanPort, localIp):
        return self.addServices(name, startWanPort, endWanPort, startLanPort, endLanPort, localIp, self.PROTOCOL_TCP)
    def addBothServices(self, name, startWanPort, endWanPort, startLanPort, endLanPort, localIp):
        return self.addServices(name, startWanPort, endWanPort, startLanPort, endLanPort, localIp, self.PROTOCOL_BOTH)

class Server(xmlobject):
    def __init__(self, name, startWanPort, endWanPort, startLanPort, endLanPort, localIp, protocol=VirtualServers.PROTOCOL_BOTH):
        if (protocol not in [VirtualServers.PROTOCOL_BOTH, VirtualServers.PROTOCOL_TCP, VirtualServers.PROTOCOL_UDP]): raise ValueError('Invalid protocol specified for port forwarding (Virtual Server)')
        if (not utils.isIpValid(localIp)): raise ValueError('Invalid ipaddress specified for port fowarding target server')
        self.VirtualServerIPName = name
        self.VirtualServerStatus = 1
        self.VirtualServerRemoteIP = ''
        self.VirtualServerWanPort = startWanPort
        self.VirtualServerWanEndPort = endWanPort
        self.VirtualServerLanPort = startLanPort
        self.VirtualServerLanEndPort = endLanPort
        self.VirtualServerIPAddress = localIp
        self.VirtualServerProtocol = protocol

class LanSettings(xmlobject):
    def __init__(self):
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
    def setDnsManual(self, primaryDns, secondaryDns=''):
        if (not utils.isIpValid(primaryDns)): raise ValueError("Invalid Primary DNS IP Address: %s" % primaryDns)
        if (secondaryDns != '' and not utils.isIpValid(secondaryDns)): raise ValueError("Invalid Secondary DNS IP Address: %s" % secondaryDns)
        self.DnsStatus = 0
        self.PrimaryDns = primaryDns
        self.SecondaryDns = secondaryDns
    def setDnsAutomatic(self):
        self.DnsStatus = 1
    def setLanAddress(self, ipaddress, netmask='255.255.255.0', url='homerouter.cpe'):
        if (not utils.isIpValid(ipaddress)): raise ValueError("Invalid LAN IP Address: %s" % ipaddress)
        self.DhcpIPAddress = ipaddress
        self.homeurl = url
    def setDhcpOn(self, startAddress, endAddress, leaseTime=86400):
        if (not utils.isIpValid(startAddress)): raise ValueError("Invalid DHCP starting IP Address: %s" % startAddress)
        if (not utils.isIpValid(endAddress)): raise ValueError("Invalid DHCP ending IP Address: %s" % endAddress)
        self.DhcpStatus = 1
        self.DhcpStartIPAddress = startAddress
        self.DhcpEndIPAddress = endAddress
        self.DhcpLeaseTime = leaseTime
    def setDhcpOff(self):
        self.DhcpStatus = 0

class macfilter(xmlobject):
    def __init__(self, value):
        if (not utils.isMacValid(value)): raise ValueError("Invalid MAC Address to filter: %s" % value)
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

class StaticHosts(xmlobject):
    def __init__(self):
        self.Hosts = []
    def addHost(self, mac, ip):
        host = Host(mac, ip)
        self.Hosts.append(host)
        host.HostIndex = len(self.Hosts)

class Host(xmlobject):
    def __init__(self, mac, ip):
        if (not utils.isMacValid(mac)): raise ValueError("Invalid static host MAC address: %s" % mac)
        if (not utils.isIpValid(ip)): raise ValueError("Invalid static host IP Address: %s" % ip)
        self.HostIndex = 0
        self.HostHw = mac
        self.HostIp = ip
        self.HostEnabled = 1

class CustomXml(xmlobject):
    def __init__(self, props, element_name=None):
        if element_name is None:
            element_name = self.__class__.__name__
        self.ele_name = element_name
        self.vals = props.copy()
    def getPropertyNames(self):
        return self.vals.keys()
    def getValue(self, property):
        return self.vals[property]
    def getElementName(self): return self.ele_name


class RouterControl(xmlobject):
    NONE = -1
    REBOOT = 1
    POWEROFF = 4
    def __init__(self, control):
        self.Control = control
    
    @classmethod
    def reboot(cls): return RouterControl(cls.REBOOT)

    @classmethod
    def poweroff(cls): return RouterControl(cls.POWEROFF)

class ddns(xmlobject):
    # <ddnss>
    # <ddns>
    # <username>hamish.mcneish@gmail.com</username>
    # <index>1</index>
    # <status>1</status>
    # <domainname>hmcneish.ddns.net</domainname>
    # <password>********</password>
    # <provider>No-IP.com</provider>
    # </ddns></ddnss>
    def __init__(self, username, password, domain, provider):
        self.username = username
        self.password = password
        self.domainname = domain
        self.provider = provider
        self.status = 1
        self.index = 0

class DdnsCollection(xmlobject):
    OPERATE_ADD = 1
    OPERATE_DELETE = 2
    OPERATE_EDIT = 3
    PROVIDER_DYNDNS = "DynDNS.org"
    PROVIDER_NOIP = "No-IP.com"
    PROVIDER_ORAY = "oray"
    def __init__(self):
        self.ddnss = []
        self.operate = self.OPERATE_ADD
    def addNoIpDdns(self, username, password, domain):
        return self.addDdns(username, password, domain, self.PROVIDER_NOIP)
    def addDynDnsDdns(self, username, password, domain):
        return self.addDdns(username, password, domain, self.PROVIDER_DYNDNS)
    def addOrayDdns(self, username, password, domain):
        return self.addDdns(username, password, domain, self.PROVIDER_ORAY)
    def addDdns(self, username, password, domain, provider):
        rec = ddns(username, password, domain, provider)
        rec.index = len(self.ddnss)
        self.ddnss.append(rec)
    def setToAdd(self):
        self.operate = self.OPERATE_ADD
    def setToDelete(self):
        self.operate = self.OPERATE_DELETE
    def setToEdit(self):
        self.operate = self.OPERATE_EDIT
