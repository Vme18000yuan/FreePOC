# FreePOC
#### 最开始学安全时候大家都喜欢分享，现在分享的人越来越少了，github上POC分享项目也逐渐不更新了。故创建此项目， 收集网上公开漏洞，并编写成yaml,python](https://github.com/Vme18000yuan/FreePOC#网络安全经历了前几年疯狂的发展这两年似乎进入了冷静期之前一些活跃的大佬也不在活跃最开始学安全时候大家都喜欢分享现在分享的人越来越少了github上poc分享项目也逐渐不更新了故创建此项目收集网上公开漏洞并编写成yamlpython),省去大家日常渗透工作中收集有效POC的时间。
<br>
部分POC使用时候需要安装 poc_tool<br>
`pip install poc_tool`
<br>


本项目免费，因工作繁忙POC收集难免会不及时欢迎大家一起提交POC, 提交POC发送邮件至 hackersolder8848@gmail.com ，提交5个以上POC将获得免费fofa数据导出服务（可绕过1W条导出限制）

<h4>感谢mortal、以及其他两位不愿意透露姓名的师傅支持</h4>


# 漏洞列表

```
大华智能物联综合管理平台readPic任意文件读取漏洞
泛微e-Mobile lang2sql 任意文件上传漏洞
红帆iOffice ioFileDown.aspx任意文件读取漏洞
IP-guard-WebServer-RCE
Kingdee-EAS myUploadFile 任意文件上传漏洞
用友GRP-U8 license_check.jsp sql注入漏洞
用友upload.jsp 任意文件上传漏洞
致远wpsAssistServlet 任意文件上传漏洞
yonyou-u8-cloud-RegisterServlet-sql                    用友u8-cloud RegisterServlet SQL注入漏洞
entsoft_fileupload_jsp_file_upload.py                  浙大恩特客户资源管理系统 fileupload.jsp 文件上传漏洞
landray_oa_sysuicomponent_file_upload.py                蓝凌OA sysUiComponent 前台任意文件上传
CellinxNVT-GetFileContent_cgi-F.yaml                    Cellinx NVT 摄像机 GetFileContent.cgi 任意文件读取漏洞
Fanwei-eoffice-InformationLleakage.yaml               泛微E-Office信息泄露漏洞(CVE-2023-2766)
JinHeOA-OfficeServer-FileUpload.yaml                   金和oa OfficeServer任意文件上传漏洞
ShiKongZhiYou-wc_db-InformationLleakage.yaml            时空智友企业流程化管控系统 wc.db 文件信息泄露漏洞
YongYouU8-cloud-RegisterServlet-sqli.yaml              用友u8-cloud RegisterServlet SQL注入漏洞
ZheDaEnTe-fileupload_jsp-FileUpload.yaml               浙大恩特客户资源管理系统fileupload 任意文件上传漏洞
zhedaenkeMailActionUpload.py                           浙大恩特客户资源管理系统MailAction 任意文件上传漏洞
zhedaenkeeditAction_SQL.py                             浙大恩特客户资源管理系统editAction SQL注入漏洞
泛微OA_E-Cology_browser.jsp_SQL注入.py                 泛微OA_E-Cology_browser.jsp_SQL注入漏洞
泛微OA_E-mobile_lang2sql_接口任意文件上传.py           泛微OA_E-mobile_lang2sql_接口任意文件上传漏洞
泛微OA_E-Office_mobile_upload_save_任意文件上传.py      泛微OA_E-Office_mobile_upload_save_任意文件上传漏洞
泛微OA_E-Office_uploadify.php_任意文件上传.py          泛微OA_E-Office_uploadify.php_任意文件上传漏洞
海康威视摄像头管理后台未授权访问.py                     海康威视摄像头管理后台未授权访问漏洞
海康威视综合安防管理平台env信息泄露.py                  海康威视综合安防管理平台env信息泄露漏洞
致远OA_A6_config.jsp_敏感信息泄漏.py                    致远OA_A6_config.jsp_敏感信息泄漏漏洞
致远OA_getSessionList.jsp_Session泄漏.py                致远OA_getSessionList.jsp_Session泄漏漏洞
致远OA_webmail.do_任意文件下载.py                       致远OA_webmail.do_任意文件下载漏洞
致远OA_帆软组件_ReportServer_目录遍历.py                致远OA_帆软组件_ReportServer_目录遍历漏洞
hongjing_app_check_in-get_org_tree-sql.py              宏景人力get_org_tree-sql注入漏洞
jindieyun_ScpSupRegHandler_uploadfile.py               金蝶云星空管理中心_ScpSupRegHandler任意文件上传漏洞
shikongzhiyou_formservice_uploadfile.py                时空智友企业流程化管控系统_formservice_文件上传漏洞
宏景人力_servlet-codesettree_sql注入.py                宏景人力_servlet-codesettree_sql注入漏洞
landray_oa_sysuicomponent_file_upload.py               蓝凌OA sysUiComponent 前台任意文件上传漏洞
shikong_Login_Any_file_read.py                         时空智友_Login任意文件读取漏洞
wangkangrce.py                                         网康下一代防火墙远程命令执行漏洞
wangkang_rce.yaml                                      网康下一代防火墙远程命令执行漏洞
wanhu_OA_any_upload_file.py                            万户OA upload.jsp 任意文件上传漏洞
H3C_ Network_Management_System_ Any_file_read.py       H3C网络管理系统  任意文件读取漏洞
jiecheng-CWSFinanceCommon-sqli.yaml                    捷诚管理信息系统 CWSFinanceCommon.asmx SQL注入漏洞
jiecheng-CWSFinanceCommon-sqli.py                      捷诚管理信息系统 CWSFinanceCommon.asmx SQL注入漏洞
array_vpn_fileread.py                                  Array VPN 任意文件读取漏洞
enjoyIT_CWSFinanceCommon_SQL.py                        昂捷商业连锁管理信息系统CWSFinanceCommon接口SQL注入漏洞
enjoyIT_CWSHr_SQL.py                                   昂捷商业连锁管理信息系统CWSHr接口SQL注入漏洞
enjoyIT_cwsoa_SQL.py                                   昂捷商业连锁管理信息系统cwsoa接口SQL注入漏洞
huawei-auth-http-readfile.py                           华为Auth-http Server任意文件读取漏洞
dahua-zhyq-deleteftp-rce.py                            大华智慧园区综合管理平台deleteFtp接口远程命令执行
dahua-zhyq-deleteftp-rce.yaml                          大华智慧园区综合管理平台deleteFtp接口远程命令执行
newcapec-CampusMobileServiceManagementPlatform-RCE.py      新开普掌上校园服务管理平台service.action远程命令执行漏洞
newcapec-CampusMobileServiceManagementPlatform-RCE.yaml     新开普掌上校园服务管理平台service.action远程命令执行漏洞
NC_Cloud_word_fileRead.py                                  用友NC Cloud word任意文件读取
dahua_zhyq_attachment_fileread.py                          大华智慧园区综合管理平台attachment_downloadByUrlAtt接口任意文件读取漏洞
tongda_down_infoleek.py                                    通达OA inc/package/down.php接口未授权访问漏洞
ezoffice_wpsservlet_upload.py                              万户协同办公平台ezoffice wpsservlet接口任意文件上传漏洞
anwang-ac-info.yaml                                        安网智能AC管理系统actpt_5g.data存在信息漏洞
hongfanOA_iorepsavexml_upload.py                           红帆OA iorepsavexml.aspx文件上传漏洞
security_products_rce.py                                   多个厂商安全设备远程命令执行漏洞
security_products_rce.yaml                                 多个厂商安全设备远程命令执行漏洞
sudaruanjian_upload.py                                     速达进存销管理系统任意文件上传漏洞
sudaruanjian_upload.yaml                                   速达进存销管理系统任意文件上传漏洞
secworld_info_leek.yaml                                    网神防火墙账号信息泄露漏洞
e-bridge-SQL.py                                            泛微云桥 e-Bridge SQL注入
aoweiya-VideoCover-upload.py                               奥威亚视屏云平台VideoCover任意文件上传
aoweiya-VideoCover-upload.yaml                             奥威亚视屏云平台VideoCover任意文件上传
```

