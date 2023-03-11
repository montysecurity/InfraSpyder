from censys.search import CensysHosts
from pprint import pprint
from os import getenv, makedirs, removedirs, system, chdir
import requests, argparse, censys

parser = argparse.ArgumentParser(description="Download files from hosts in Censys results provided a Censys query and patterns to match.")
parser.add_argument("-q", "--query", type=str, help="Censys Query")
parser.add_argument("-p", "--patterns", type=str, help="File containing patterns to match (POSIX regex)")

args = parser.parse_args()
censys_query = args.query
pattern_file = args.patterns

endpoints = set()

example = dict({'ip': '101.43.51.150', 'services': [{'_decoded': 'ssh', '_encoding': {'banner': 'DISPLAY_UTF8', 'banner_hex': 'DISPLAY_HEX'}, 'banner': 'SSH-2.0-OpenSSH_7.4', 'banner_hashes': ['sha256:be0da7ee170f9a69bc13b9e61ecfc9110c27db40f3f2e4c0ffae6741f064af8a'], 'banner_hex': '5353482d322e302d4f70656e5353485f372e34', 'extended_service_name': 'SSH', 'labels': ['remote-access'], 'observed_at': '2023-03-03T14:12:02.862402455Z', 'perspective_id': 'PERSPECTIVE_NTT', 'port': 22, 'service_name': 'SSH', 'software': [{'uniform_resource_identifier': 'cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*', 'part': 'a', 'vendor': 'OpenBSD', 'product': 'OpenSSH', 'version': '7.4', 'other': {'family': 'OpenSSH'}, 'source': 'OSI_APPLICATION_LAYER'}], 'source_ip': '167.248.133.118', 'ssh': {'endpoint_id': {'_encoding': {'raw': 'DISPLAY_UTF8'}, 'raw': 'SSH-2.0-OpenSSH_7.4', 'protocol_version': '2.0', 'software_version': 'OpenSSH_7.4'}, 'kex_init_message': {'kex_algorithms': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256'], 'host_key_algorithms': ['ssh-rsa', 'rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519'], 'client_to_server_ciphers': ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'], 'server_to_client_ciphers': ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'], 'client_to_server_macs': ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'], 'server_to_client_macs': ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'], 'client_to_server_compression': ['none', 'zlib@openssh.com'], 'server_to_client_compression': ['none', 'zlib@openssh.com'], 'first_kex_follows': False}, 'algorithm_selection': {'kex_algorithm': 'curve25519-sha256@libssh.org', 'host_key_algorithm': 'ecdsa-sha2-nistp256', 'client_to_server_alg_group': {'cipher': 'aes128-ctr', 'mac': 'hmac-sha2-256', 'compression': 'none'}, 'server_to_client_alg_group': {'cipher': 'aes128-ctr', 'mac': 'hmac-sha2-256', 'compression': 'none'}}, 'server_host_key': {'fingerprint_sha256': '2fb73129725196a987009644dd65fa1cea3a9fe9a040434bbbd562402e9d0161', 'ecdsa_public_key': {'_encoding': {'b': 'DISPLAY_BASE64', 'gx': 'DISPLAY_BASE64', 'gy': 'DISPLAY_BASE64', 'n': 'DISPLAY_BASE64', 'p': 'DISPLAY_BASE64', 'x': 'DISPLAY_BASE64', 'y': 'DISPLAY_BASE64'}, 'b': 'WsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEs=', 'curve': 'P-256', 'gx': 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY=', 'gy': 'T+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=', 'length': 256, 'n': '/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVE=', 'p': '/////wAAAAEAAAAAAAAAAAAAAAD///////////////8=', 'x': 'wT+Edjrrv8L3f4u9E6TIT0aX88UaE0mG6I1NvzkwmSY=', 'y': 'cTq+XnBf/CDlGIuAe+FrF5UHIBKPyCgvjfRQSfI3jHo='}}, 'hassh_fingerprint': '86bc3242de3b118cbf86ce2de8f2a13b'}, 'transport_fingerprint': {'raw': '28960,64,true,MSTNW,1424,false,false'}, 'transport_protocol': 'TCP', 'truncated': False}, {'_decoded': 'http', '_encoding': {'banner': 'DISPLAY_UTF8', 'banner_hex': 'DISPLAY_HEX'}, 'banner': 'HTTP/1.1 404 Not Found\r\nDate:  <REDACTED>\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n', 'banner_hashes': ['sha256:8d83eccca809d058a7c7d18f630f7341ea8b88f699cb4c6c30623787caf431a9'], 'banner_hex': '485454502f312e3120343034204e6f7420466f756e640d0a446174653a20203c52454441435445443e0d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a436f6e74656e742d4c656e6774683a20300d0a', 'extended_service_name': 'HTTP', 'http': {'request': {'method': 'GET', 'uri': 'http://101.43.51.150:4567/', 'headers': {'Accept': ['*/*'], '_encoding': {'Accept': 'DISPLAY_UTF8', 'User_Agent': 'DISPLAY_UTF8'}, 'User_Agent': ['Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)']}}, 'response': {'protocol': 'HTTP/1.1', 'status_code': 404, 'status_reason': 'Not Found', 'headers': {'Content_Type': ['text/plain'], '_encoding': {'Content_Type': 'DISPLAY_UTF8', 'Date': 'DISPLAY_UTF8', 'Content_Length': 'DISPLAY_UTF8'}, 'Date': ['<REDACTED>'], 'Content_Length': ['0']}, 'body_size': 0}, 'supports_http2': False}, 'observed_at': '2023-03-04T00:59:53.580269701Z', 'perspective_id': 'PERSPECTIVE_NTT', 'port': 4567, 'service_name': 'HTTP', 'source_ip': '167.248.133.44', 'transport_protocol': 'TCP', 'truncated': False}, {'_decoded': 'banner_grab', '_encoding': {'banner': 'DISPLAY_UTF8', 'certificate': 'DISPLAY_HEX', 'banner_hex': 'DISPLAY_HEX'}, 'banner': '\x15\x03\x03\x00\x02\x02\n', 'banner_grab': {'_encoding': {'banner': 'DISPLAY_BASE64'}, 'banner': 'FQMDAAICCg==', 'transport': 'TCP'}, 'banner_hashes': ['sha256:e7488a7bc234fd3af5800dfd2f1fdbc866002c14f42d44606aa82341786aca80'], 'banner_hex': '1503030002020a', 'certificate': '0beb769997c9a02d979e56e330cd4209902e162fd490f9c1f12ea790f0cfa7ea', 'extended_service_name': 'UNKNOWN', 'observed_at': '2023-03-03T19:46:59.235678006Z', 'perspective_id': 'PERSPECTIVE_ORANGE', 'port': 33889, 'service_name': 'UNKNOWN', 'source_ip': '167.94.145.60', 'tls': {'version_selected': 'TLSv1_3', 'cipher_selected': 'TLS_AES_128_GCM_SHA256', 'certificates': {'_encoding': {'leaf_fp_sha_256': 'DISPLAY_HEX'}, 'leaf_fp_sha_256': '0beb769997c9a02d979e56e330cd4209902e162fd490f9c1f12ea790f0cfa7ea', 'leaf_data': {'names': ['bing.com'], 'subject_dn': 'C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, OU=Microsoft IT, CN=bing.com', 'issuer_dn': 'C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, OU=Microsoft IT, CN=bing.com', 'pubkey_bit_size': 2048, 'pubkey_algorithm': 'RSA', 'tbs_fingerprint': 'f8f238b26c8bf628631e4dd5cc9df4f1006f0e3b9f8ceb8645987343cd863b46', 'fingerprint': '0beb769997c9a02d979e56e330cd4209902e162fd490f9c1f12ea790f0cfa7ea', 'issuer': {'common_name': ['bing.com'], 'locality': ['Redmond'], 'organization': ['Microsoft Corporation'], 'organizational_unit': ['Microsoft IT'], 'province': ['Washington'], 'country': ['US']}, 'subject': {'common_name': ['bing.com'], 'locality': ['Redmond'], 'organization': ['Microsoft Corporation'], 'organizational_unit': ['Microsoft IT'], 'province': ['Washington'], 'country': ['US']}, 'public_key': {'key_algorithm': 'RSA', 'rsa': {'_encoding': {'modulus': 'DISPLAY_BASE64', 'exponent': 'DISPLAY_BASE64'}, 'modulus': 'gUghvxC/IEEr5jvDAbtOwGzO0XhVnnLLzcZrgxj8PQSJKZBSLvX4F6pnqqnOtTQUlpj+J9QUww1aojH6H62j7AO1ytU/UcnrtpqZiRcmpzx2EVMpSEeWd7dlp8GHozZ3vHpHAo5FKpcEVGy+8tVKn+Zf2N6kUCsPVy5Z2J9llqNuwI9OfbePjFXdh9gKh0OnylhAczQw3ZOTU7aE2w/Ui7OUfOBmqu5hgGpBGNYriJbANguGiWVWiN6nyn+Ac2E/sp6dN4I7BYQA8y0Fs/N+yZoA2sPUk4gZ/8jJwpaAFLKbGQT+wm06NFFIf4V7Aa1OOlCCZeOZaVkCqnyTGQ0Ucw==', 'exponent': 'AAEAAQ==', 'length': 256}, 'fingerprint': 'a9ac845caa76b87b9bc7b4a9a5013200c096321e4665fd09f111a30118684111'}, 'signature': {'self_signed': True, 'signature_algorithm': 'SHA256-RSA'}}}, '_encoding': {'ja3s': 'DISPLAY_HEX'}, 'ja3s': '069d8b151929dbfa059815cf2492cbf4'}, 'transport_protocol': 'TCP', 'truncated': False}, {'_decoded': 'http', '_encoding': {'banner': 'DISPLAY_UTF8', 'certificate': 'DISPLAY_HEX', 'banner_hex': 'DISPLAY_HEX'}, 'banner': 'HTTP/1.1 200 OK\r\nServer: nginx/1.14.0 (Ubuntu)\r\nDate:  <REDACTED>\r\nContent-Type: text/html\r\nContent-Length: 692\r\nLast-Modified: Sun, 05 Feb 2023 15:05:24 GMT\r\nConnection: keep-alive\r\nETag: "63dfc5b4-2b4"\r\nAccept-Ranges: bytes\r\n', 'banner_hashes': ['sha256:91f9dda93300bc6143be7b43e03763a8256441685235e2b873ed7bb6fdabe8a5'], 'banner_hex': '485454502f312e3120323030204f4b0d0a5365727665723a206e67696e782f312e31342e3020285562756e7475290d0a446174653a20203c52454441435445443e0d0a436f6e74656e742d547970653a20746578742f68746d6c0d0a436f6e74656e742d4c656e6774683a203639320d0a4c6173742d4d6f6469666965643a2053756e2c2030352046656220323032332031353a30353a323420474d540d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a455461673a202236336466633562342d326234220d0a4163636570742d52616e6765733a2062797465730d0a', 'certificate': '4de3278507c89d2242a12c20b74878e3f84970c463a924771f156a3da7d7b5a1', 'extended_service_name': 'HTTPS', 'http': {'request': {'method': 'GET', 'uri': 'https://101.43.51.150:60000/', 'headers': {'Accept': ['*/*'], '_encoding': {'Accept': 'DISPLAY_UTF8', 'User_Agent': 'DISPLAY_UTF8'}, 'User_Agent': ['Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)']}}, 'response': {'protocol': 'HTTP/1.1', 'status_code': 200, 'status_reason': 'OK', 'headers': {'Last_Modified': ['Sun, 05 Feb 2023 15:05:24 GMT'], '_encoding': {'Last_Modified': 'DISPLAY_UTF8', 'Accept_Ranges': 'DISPLAY_UTF8', 'Content_Length': 'DISPLAY_UTF8', 'Date': 'DISPLAY_UTF8', 'Connection': 'DISPLAY_UTF8', 'Content_Type': 'DISPLAY_UTF8', 'Etag': 'DISPLAY_UTF8', 'Server': 'DISPLAY_UTF8'}, 'Accept_Ranges': ['bytes'], 'Content_Length': ['692'], 'Date': ['<REDACTED>'], 'Connection': ['keep-alive'], 'Content_Type': ['text/html'], 'Etag': ['"63dfc5b4-2b4"'], 'Server': ['nginx/1.14.0 (Ubuntu)']}, '_encoding': {'html_tags': 'DISPLAY_UTF8', 'body': 'DISPLAY_UTF8', 'body_hash': 'DISPLAY_UTF8', 'html_title': 'DISPLAY_UTF8'}, 'html_tags': ['<title>VIPER</title>', '<meta charset="UTF-8" />', '<meta http-equiv="X-UA-Compatible" content="IE=edge" />'], 'body_size': 692, 'body': '<!DOCTYPE html>\n<html lang="en">\n  <head>\n    <meta charset="UTF-8" />\n    <meta http-equiv="X-UA-Compatible" content="IE=edge" />\n    <meta\n      name="viewport"\n      content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0;"\n    />\n    <title>VIPER</title>\n    <link rel="icon" href="/favicon.png" type="image/x-icon" />\n    <link rel="stylesheet" href="./umi.8b98b119.css" />\n    <script>\n      window.routerBase = "/";\n    </script>\n    <script>\n      //! umi version: 3.5.36\n    </script>\n  </head>\n  <body>\n    <noscript>Sorry, we need js to run correctly!</noscript>\n    <div id="root"></div>\n\n    <script src="./umi.9e7a6f63.js"></script>\n  </body>\n</html>\n', 'favicons': [{'size': 7241, 'name': 'https://101.43.51.150:60000/favicon.png', 'md5_hash': 'a7469955bff5e489d2270d9b389064e1'}], 'body_hashes': ['sha256:832d9ae1340c480940d2f670e7ef6ec0516b986f85e129a0aae32dc709aefa73', 'sha1:a4b626828d30cd55705483399144e8185a388ca6'], 'body_hash': 'sha1:a4b626828d30cd55705483399144e8185a388ca6', 'html_title': 'VIPER'}, 'supports_http2': False}, 'jarm': {'_encoding': {'fingerprint': 'DISPLAY_HEX', 'cipher_and_version_fingerprint': 'DISPLAY_HEX', 'tls_extensions_sha256': 'DISPLAY_HEX'}, 'fingerprint': '21d19d00021d21d21c21d19d21d21dd63eb481052cd655ca2b1b4e0f7740c9', 'cipher_and_version_fingerprint': '21d19d00021d21d21c21d19d21d21d', 'tls_extensions_sha256': 'd63eb481052cd655ca2b1b4e0f7740c9', 'observed_at': '2023-02-27T15:50:00.065846941Z'}, 'observed_at': '2023-03-03T01:11:55.281548270Z', 'perspective_id': 'PERSPECTIVE_TATA', 'port': 60000, 'service_name': 'HTTP', 'software': [{'uniform_resource_identifier': 'cpe:2.3:a:nginx:nginx:1.14.0:*:*:*:*:*:*:*', 'part': 'a', 'vendor': 'nginx', 'product': 'nginx', 'version': '1.14.0', 'other': {'family': 'nginx'}, 'source': 'OSI_APPLICATION_LAYER'}], 'source_ip': '167.94.138.44', 'tls': {'version_selected': 'TLSv1_2', 'cipher_selected': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'certificates': {'_encoding': {'leaf_fp_sha_256': 'DISPLAY_HEX'}, 'leaf_fp_sha_256': '4de3278507c89d2242a12c20b74878e3f84970c463a924771f156a3da7d7b5a1', 'leaf_data': {'subject_dn': 'C=CN, ST=d1d38ec9, L=d1d38ec9, O=d1d38ec9, OU=d1d38ec9, CN=d1d38ec9', 'issuer_dn': 'C=CN, ST=0d72da0c, L=0d72da0c, O=0d72da0c, OU=0d72da0c, CN=0d72da0c', 'pubkey_bit_size': 4096, 'pubkey_algorithm': 'RSA', 'tbs_fingerprint': 'ec697052c21bc03a88719ad2290a18db7022ded2dcf7cb5674ae2a30ae16b763', 'fingerprint': '4de3278507c89d2242a12c20b74878e3f84970c463a924771f156a3da7d7b5a1', 'issuer': {'common_name': ['0d72da0c'], 'locality': ['0d72da0c'], 'organization': ['0d72da0c'], 'organizational_unit': ['0d72da0c'], 'province': ['0d72da0c'], 'country': ['CN']}, 'subject': {'common_name': ['d1d38ec9'], 'locality': ['d1d38ec9'], 'organization': ['d1d38ec9'], 'organizational_unit': ['d1d38ec9'], 'province': ['d1d38ec9'], 'country': ['CN']}, 'public_key': {'key_algorithm': 'RSA', 'rsa': {'_encoding': {'modulus': 'DISPLAY_BASE64', 'exponent': 'DISPLAY_BASE64'}, 'modulus': '3Wjee3xpnsTqEqLVPJ/2ucJCY2CviTfcSRsZjZ/+8X0tF0m0IrkN9Cd1YQZ9zqquryqn9ZD/lxAt4b5LoV/TRwRXuDuZ/zcAK39Kf6NURLiY1Sh8f9KVslFCC+fvLeOLKwtsX80W8+g3Q5sP3XeRVn6LzyWMKhQSGFD3xRFQ4S2y4jAEDQDBhl73+iUWopd3fyXQctgHVvNnYAgf7o4maXsqJb8jYSOlYZOD8UiGSsw2RIddPN5+e2A/sIFMvz5rgjVdLgm6h+rRrWm6P4RDrG1Wamc1nPq2f/O/yFEIwXV66U7vGClC2Jbmn9wPKWADsmzJjHK++ZCnaXdMw/yRE6hWSofS9XKIFD9zlJ2LIwxm3xNcUyB9iCo9XOMP+GQBR0FI+rXg6MSH5mHLpmVYGk69lB5EUBfvG+RUGO6deKgvznPtMw+/HQxwTGvT+DYnym7t8qNelCUm6wbDrQgCPxlQQfkzlPDTqv2WhfWVovYjYKWK+BlDJNG7eSgfKPW9s4a53tJ67Bvoptf27dLmuRO9DtyE+f190pGPVjFZU200+xZMuNVIK06aoKNbAOwvlLOAK8qNWqQWWpNYSpNarxgQYcrNkGh+PxFxCsKCajhFmfmj1bhb4IB3m8NO7cS7TlE8ISQwUbuuu9Jz1Qvkw8X4Pu4m9Ba6xHGASLII690=', 'exponent': 'AAEAAQ==', 'length': 512}, 'fingerprint': '82229c9717af97888d9e6b18b79fed4797ce3120c4b9bec4010e2220e9466ca5'}, 'signature': {'signature_algorithm': 'SHA256-RSA', 'self_signed': False}}}, 'server_key_exchange': {'ec_params': {'named_curve': 29}}, 'session_ticket': {'length': 176, 'lifetime_hint': 3600}, '_encoding': {'ja3s': 'DISPLAY_HEX'}, 'ja3s': 'a4a4c81b00b746b978f1513c9d74831e'}, 'transport_protocol': 'TCP', 'truncated': False}], 'location': {'continent': 'Asia', 'country': 'China', 'country_code': 'CN', 'postal_code': '', 'timezone': 'Asia/Shanghai', 'coordinates': {'latitude': 34.7732, 'longitude': 113.722}, 'registered_country': 'China', 'registered_country_code': 'CN'}, 'location_updated_at': '2023-02-19T05:04:36.112336Z', 'autonomous_system': {'asn': 45090, 'description': 'TENCENT-NET-AP Shenzhen Tencent Computer Systems Company Limited', 'bgp_prefix': '101.43.0.0/18', 'name': 'TENCENT-NET-AP Shenzhen Tencent Computer Systems Company Limited', 'country_code': 'CN'}, 'autonomous_system_updated_at': '2023-02-19T05:04:36.112379Z', 'dns': {}, 'last_updated_at': '2023-03-04T00:59:54.447Z', 'labels': ['remote-access']})
censys_api_id = getenv("CENSYS_API_ID")
censys_api_secret = getenv("CENSYS_API_SECRET")
censys_api = CensysHosts(censys_api_id, censys_api_secret)
censys_query = "(Directory listing for msf4)"
#censys_search = censys_api.search(censys_query)
#try:
#    censys_results = censys_search.view_all()
#except censys.common.exceptions.CensysRateLimitExceededException:
#    print("Reached API Quota")
#    quit()

for r in example:
    print(r)
    print(example["ip"])

quit()


ip = example["ip"]
services = example["services"]

for service in services:
    service_name = service["extended_service_name"]
    service_port = service["port"]
    if service_name in [ "HTTP", "HTTPS" ]:
        endpoint = str(service_name.lower() + "://" + ip + ":" + str(service_port))
        endpoints.add(endpoint)

endpoints = [ "http://0.0.0.0:8000" ]

# for each endpoint
    # create endpoint dir
    # spider each dir
    # only download files containing string from "filters" dictionary
    # Add support for proxies

# remove findings and .wget.log at init
for endpoint in endpoints:
    try:
        requests.get(endpoint, verify=False)
    except requests.exceptions.ConnectionError:
        print(f"{endpoint} is offline")
        continue
    #dir_name = str(endpoints_dir) + str(endpoint).replace(".", "_").replace(":", "_").replace("/", "_")
    #makedirs(dir_name)
    # Write log file for parsing
    # TO DO: Convert this to a proper spider
    cmd = f"wget --spider --no-parent --recursive --no-directories {endpoint} 2>> .wget.log"
    system(cmd)

f = open(pattern_file, "r")
patterns = f.readlines()
f.close()

for pattern in patterns:
    cmd = "cat .wget.log | grep http | grep " + pattern.strip() + " | sed 's/.* http/http/g' >> .findings.log && sort -ufo .findings.log .findings.log"
    system(cmd)

f = open(".findings.log", "r")
findings = f.readlines()
f.close()
#print(findings)

system("mkdir findings")
chdir("findings")
for finding in findings:
    print(f"Downloading {finding}".strip())
    cmd = f"wget -q {finding}"
    system(cmd)
chdir("../")
