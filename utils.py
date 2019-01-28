from IPy import IP
import re

def isMacValid(mac): return re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())
def isIpValid(ip):
    try:
        IP(ip)
        return True
    except:
        return False

def getRange(vals, val):
    ''' Returns the position in a descendng range of values
    E.g, [10,5,2]
    Returns 0:x>=10, 1:x>5, 2:x>2, 3:x<=2'''
    for i in range(len(vals)+1):
        if (i == 0):
            if (val >= vals[i]): return i
        elif (i == len(vals)):
            if (val <= vals[i-1]): return i
        else:
            if (val > vals[i]): return i
    return 0
