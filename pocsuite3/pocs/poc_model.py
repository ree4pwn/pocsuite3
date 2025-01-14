import os, base64

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = 'SSVID-97207 CVE-2018-7600'  # ssvid
    version = '1.0'
    author = ['seebug', 'cz']
    vulDate = '2018-03-08'
    createDate = '2018-04-12'
    updateDate = '2018-04-13'
    references = ['https://www.seebug.org/vuldb/ssvid-97207']
    name = 'Drupal core Remote Code Execution'
    appPowerLink = ''
    appName = 'Drupal'
    appVersion = '7-7.57, 8.x-8.3.8, 8.4.x-5, 8.5.0'
    vulType = 'Romote Code Execution'
    desc = '''由于Drupal对Form API（FAPI）的AJAX请求的输入没有进行严格过滤，使得攻击者有机会将恶意荷载注入内部表单结构，从而导致Drupal在没有进行用户认证的情况下执行恶意荷载。'''
    samples = []
    install_requires = ['']
    pocDesc = ''
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

    def _verify(self):
        return super()._verify()

    def _attack(self):
        return super()._attack()
    
register_poc(DemoPOC)