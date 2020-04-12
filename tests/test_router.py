import os
import unittest
import huawei_lte.router as lte
import huawei_lte.xmlobjects as xmlobjects

class Ethernet(unittest.TestCase):
    
    def test_router_features(self):
        router = lte.B525Router('192.168.9.1')
        router.login('admin', os.getenv('B525_PASSWORD'))
        try:
            print(router.features)
            self.assertTrue(True)
        except:
            self.assertTrue(False)
        finally:
            router.logout()

    def test_set_static(self):
        mode = xmlobjects.ConnectionMode()
        mode.staticipmtu = 1480
        mode.ipaddress = ''
        mode.netmask = ''
        mode.gateway = ''

        #Working example
        try:
            mode.set(mode.MODE_STATIC, {'ipaddress': '192.168.1.3', 'gateway': '192.168.1.1'})
            self.assertEqual(mode.connectionmode, mode.MODE_STATIC)
            self.assertEqual(mode.netmask, '255.255.255.0')
            self.assertEqual(mode.ipaddress, '192.168.1.3')
            self.assertEqual(mode.gateway, '192.168.1.1')
        except Exception, err:
            self.assertTrue(False, err.message)

        #Required parameters
        try:
            mode.set(mode.MODE_STATIC, {''})
            self.assertTrue(False, 'Missing required params')
        except ValueError, err:
            self.assertTrue('ipaddress must be provided' in err.message)
            self.assertEqual(mode.netmask, '255.255.255.0')
            self.assertEqual(mode.ipaddress, '192.168.1.3')
            self.assertEqual(mode.gateway, '192.168.1.1')

        try:
            mode.set(mode.MODE_STATIC, {'ipaddress': '192.168.1.3'})
            self.assertTrue(True, 'Gateway set already')
        except:
            self.assertTrue(False, 'Gateway set already')
        
        try:
            mode.gateway = ''
            mode.set(mode.MODE_STATIC, {'ipaddress': '192.168.1.3'})
            self.assertTrue(False, 'Missing gateway')
        except ValueError, err:
            self.assertTrue('gateway must be provided' in err.message.lower())
            self.assertEqual(mode.netmask, '255.255.255.0')
            self.assertEqual(mode.ipaddress, '192.168.1.3')
            self.assertEqual(mode.gateway, '')

        #Bad IP Address
        try:
            mode.set(mode.MODE_STATIC, {'ipaddress': 'fred', 'gateway': '192.168.1.1'})
            self.assertTrue(False, 'Invalid IP Address')
        except ValueError, err:
            self.assertTrue('invalid ip address' in err.message.lower())

    def test_set_dynamic(self):
        mode = xmlobjects.ConnectionMode()
        mode.dynamicsetdnsmanual = 0
        mode.dynamicprimarydns = '0.0.0.0'
        mode.dynamicsecondarydns = '0.0.0.0'
        mode.dynamicipmtu = 1480
        try:
            mode.set(mode.MODE_AUTO, {'primarydns': '8.8.8.8', 'secondarydns': '8.8.4.4'})
            self.assertEqual(mode.dynamicsetdnsmanual, 1)
            self.assertEqual(mode.dynamicprimarydns, '8.8.8.8')
            self.assertEqual(mode.dynamicsecondarydns, '8.8.4.4')
            self.assertEqual(mode.dynamicipmtu, 1480)
        except Exception, err:
            self.assertTrue(False, err.message)

        try:
            mode.set(mode.MODE_AUTO, {'dnsmanual': 0})
            self.assertEqual(mode.dynamicsetdnsmanual, 0)
            self.assertEqual(mode.dynamicprimarydns, '8.8.8.8')
            self.assertEqual(mode.dynamicsecondarydns, '8.8.4.4')
            self.assertEqual(mode.dynamicipmtu, 1480)
        except Exception, err:
            self.assertTrue(False, err.message)

        try:
            mode.set(mode.MODE_AUTO, {'mtu': 1500})
            self.assertEqual(mode.dynamicsetdnsmanual, 0)
            self.assertEqual(mode.dynamicprimarydns, '8.8.8.8')
            self.assertEqual(mode.dynamicsecondarydns, '8.8.4.4')
            self.assertEqual(mode.dynamicipmtu, 1500)
        except Exception, err:
            self.assertTrue(False, err.message)


        #Bad IP Address
        try:
            mode.set(mode.MODE_AUTO, {'primarydns': 'fred'})
            self.assertTrue(False, 'Invalid IP Address')
        except ValueError, err:
            self.assertTrue('invalid ip address' in err.message.lower())
            self.assertEqual(mode.dynamicsetdnsmanual, 0)
            self.assertEqual(mode.dynamicprimarydns, '8.8.8.8')
            self.assertEqual(mode.dynamicsecondarydns, '8.8.4.4')
            self.assertEqual(mode.dynamicipmtu, 1500)

        #Bad IP Address
        try:
            mode.set(mode.MODE_AUTO, {'secondarydns': 'fred'})
            self.assertTrue(False, 'Invalid IP Address')
        except ValueError, err:
            self.assertTrue('invalid ip address' in err.message.lower())
            self.assertEqual(mode.dynamicsetdnsmanual, 0)
            self.assertEqual(mode.dynamicprimarydns, '8.8.8.8')
            self.assertEqual(mode.dynamicsecondarydns, '8.8.4.4')
            self.assertEqual(mode.dynamicipmtu, 1500)

    def test_set_ppoe(self):
        mode = xmlobjects.ConnectionMode()
        mode.pppoeauth = 0
        mode.pppoepwd = ''
        mode.pppoeuser = ''
        try:
            mode.set(mode.MODE_PPPOE, {'username': 'fred', 'password': 'secret', 'authmode': mode.AUTH_CHAP})
            self.assertEqual(mode.pppoeuser, 'fred')
            self.assertEqual(mode.pppoepwd, 'secret')
            self.assertEqual(mode.pppoeauth, mode.AUTH_CHAP)
            self.assertNotEqual(mode.pppoeauth, 0)
        except Exception, err:
            self.assertTrue(False, err.message)
        
        try:
            mode.pppoepwd = ''
            mode.pppoeuser = ''
            mode.pppoeauth = mode.AUTH_AUTO
            mode.set(mode.MODE_PPPOE, {'username': 'fred'})
            self.assertTrue(False, 'Missing password')
        except Exception, err:
            self.assertTrue('password must be provided' in err.message.lower())
            self.assertEqual(mode.pppoeuser, '')
            self.assertEqual(mode.pppoepwd, '')
            self.assertEqual(mode.pppoeauth, mode.AUTH_AUTO)

    def test_set_mode(self):
        router = lte.B525Router('192.168.8.1')
        router.login('admin', os.getenv('B525_PASSWORD'))
        try:
            result = router.ethernet.set_auto({'primarydns': '8.8.8.8', 'secondarydns': '8.8.4.4'})
            print(result)
            print('-----')
            result = router.ethernet.set_auto({'username': 'fred', 'password': 'secret'})
            print(result)
            print('-----')
            print(router.ethernet.settings)
            print('-----')
            print(router.ethernet.status)
            print('-----')
            print(router.ethernet.connection)
        finally:
            router.logout()
