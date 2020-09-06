import huawei_lte.router as lte
import huawei_lte.xmlobjects as xmlobjects
from huawei_lte.errors import RouterError
import datetime
import time

with open("/huaweiB525/reboot.log", mode='a') as file:
    file.write('%s\n' %datetime.datetime.now())

router = lte.B525Router('192.168.8.1')
router.login(username='admin', password='14032020')

router.dataswitch.set_dataswitch_off()
router.dataswitch.set_dataswitch_on()

router.logout()

