import xmlobjects as xmlobjects

class RouterError(Exception):

    __ERRORS = [
        [2000, 'Python API: %s - %s'],
        [100001, 'An unkown error occurred'],
        [100002, 'The router does not support this function'],
        [100003, 'You have no rights to access this function'],
        [100004, 'The system is busy'],
        [100005, 'Format error'], #TODO: This is not very discriptive, XML format?
        [100006, 'Parameter error'], #TODO: Assume invalid attribute, or missing attribute?
        [100007, 'Save config file error'],
        [100008, 'Get config file error'],

        [101001, 'No SIM card, or invalid SIM card'],
        [101002, 'Check SIM card PIN lock'],
        [101003, 'Check SIM card PUN lock'],
        [101004, 'Check SIM card is usable'],
        [101005, 'Enable PIN failed'],
        [101006, 'Disable PIN failed'],
        [101007, 'Unlock PIN failed'],
        [101008, 'Disable Auto PIN failed'],
        [101009, 'Enable Auto PIN failed'],

        [108001, 'The username is wrong'],
        [108002, 'The password is wrong'],
        [108003, 'The user is already logged in'],
        [108004, 'Modify password failed'],
        [108005, 'Too many users logged in'],
        [108006, 'The username and/or password are wrong'],
        [108007, 'Logging in too many times'],
        [108010, 'Access denied, logins are too frequent'],

        [118001, 'Cradle get current connected user IP failed'],
        [118002, 'Cradle get current connected user MAC failed'],
        [118003, 'Cradle set MAC failed'],
        [118004, 'Cradle get WAN information failed'],
        [118005, 'Cradle coding failure'],
        [118006, 'Cradle update profile failed'],

        [120001, 'Voice is busy'],
        [125001, 'Invalid authentication token'],
        [125002, 'Invalid session'],
        [125003, 'Invalid session token']
        #TODO: Add 9003 occurring when setting static ip addresses
    ]

    @classmethod
    def hasError(cls, xml): return '<error>' in xml

    @classmethod
    def getErrorMessage(cls, code):
        code = int(code)
        for err in cls.__ERRORS:
            if (err[0] == code): return err[1]
        return 'An unknown error occurred'

    def __init__(self, response):
        error = xmlobjects.Error()
        error.parseXML(response)
        self.code = error.code
        self.message = error.message
        super(RouterError, self).__init__(self.code +": "+self.message)
