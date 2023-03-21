from censys.search import CensysHosts
from shodan import Shodan
from pprint import pprint
from os import getenv, makedirs, removedirs, system, chdir
import requests, argparse, censys

parser = argparse.ArgumentParser(description="Download files from hosts in Censys results provided a Censys query and patterns to match.")
parser.add_argument("-c", "--censys-query", type=str, help="Censys Query")
parser.add_argument("-s", "--shodan-query", type=str, help="Shodan Query")
parser.add_argument("-p", "--patterns", type=str, help="File containing patterns to match (POSIX regex)")

args = parser.parse_args()
censys_query = args.censys_query
shodan_query = args.shodan_query
pattern_file = args.patterns
shodan_key = getenv("SHODAN_API_KEY")
shodan_api = Shodan(shodan_key)


endpoints = set()
if shodan_query:
    for result in shodan_api.search_cursor(shodan_query):
        ip = str(result["ip_str"])
        port = str(result["port"])
        url = f"http://{ip}:{port}"
        #url_tls = f"https://{ip}:{port}"
        endpoints.add(url)
        domains = result["hostnames"]
        if len(domains) > 0:
            for domain in domains:
                url = f"http://{domain}:{port}"
                #url_tls = f"https://{domain}:{port}"
                endpoints.add(url)

#censys_api_id = getenv("CENSYS_API_ID")
#censys_api_secret = getenv("CENSYS_API_SECRET")
#censys_api = CensysHosts(censys_api_id, censys_api_secret)
#censys_query = "(Directory listing for msf4)"
#censys_search = censys_api.search(censys_query)
#try:
#    censys_results = censys_search.view_all()
#except censys.common.exceptions.CensysRateLimitExceededException:
#    print("Reached API Quota")
#    quit()

#for r in example:
#    print(r)
#    print(example["ip"])

#quit()


#ip = example["ip"]
#services = example["services"]

#for service in services:
#    service_name = service["extended_service_name"]
#    service_port = service["port"]
#    if service_name in [ "HTTP", "HTTPS" ]:
#        endpoint = str(service_name.lower() + "://" + ip + ":" + str(service_port))
#        endpoints.add(endpoint)

#endpoints = [ "http://0.0.0.0:8000" ]

# for each endpoint
    # create endpoint dir
    # spider each dir
    # only download files containing string from "filters" dictionary
    # Add support for proxies

f = open(pattern_file, "r")
patterns = f.readlines()
f.close()

makedirs("downloads")
chdir("downloads")

# remove findings and .wget.log at init
for endpoint in endpoints:
    print(endpoint)
    try:
        requests.get(endpoint, verify=False, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"{endpoint} is offline")
        continue
    except requests.exceptions.ReadTimeout:
        print(f"{endpoint} is offline")
        continue
    dir_name = str(endpoint).replace(".", "_").replace(":", "_").replace("/", "_")
    makedirs(dir_name)
    chdir(dir_name)
    # Write log file for parsing
    # TO DO: Convert this to a proper spider
    cmd = f"wget --spider --no-parent --recursive --no-directories {endpoint} 2>> wget.log"
    system(cmd)
    for pattern in patterns:
        cmd = "cat wget.log | grep http | grep " + pattern.strip() + " | sed 's/.* http/http/g' >> findings.log && sort -ufo findings.log findings.log"
        system(cmd)
    f = open("findings.log", "r")
    findings = f.readlines()
    f.close()
    print(findings)
    makedirs("findings")
    chdir("findings")
    for finding in findings:
        print(f"Downloading {finding}".strip())
        cmd = f"wget {finding}"
        system(cmd)
    chdir("../../")
