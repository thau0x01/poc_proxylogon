# poc_proxylogon
Microsoft Exchange ProxyLogon PoC (CVE-2021-26855)

This is script was originaly made by celesian to exploit this CVE.
Then i updated it to exploit an exchange server vulnerable to SSRE but it got a Shell exploiting the EWS feature.

The `ssrf_exploit.py` was was initially designed to get a valid MS Exchange admin account session and then upload a webshell abusing the EWS features as other clients do, like uploading e-mail attachments to the exchange server and then abusing export features to trigger the payload.
