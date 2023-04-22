from censys.search import CensysHosts
from shodan import Shodan
from pprint import pprint
from os import getenv, makedirs, removedirs, system, chdir, remove
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import subprocess as sp
import requests, argparse, censys

colorama_init()

parser = argparse.ArgumentParser(description="Automatically spider the result set of a Censys/Shodan search and download all files where the file name matches a regex.")
parser.add_argument("-c", "--censys-query", type=str, help="Censys Query")
parser.add_argument("-s", "--shodan-query", type=str, help="Shodan Query")
parser.add_argument("-p", "--patterns", type=str, help="File containing patterns to match (POSIX regex)")

args = parser.parse_args()
censys_query = args.censys_query
shodan_query = args.shodan_query
pattern_file = args.patterns
endpoints = set()

if not pattern_file:
    print("Specify Pattern File with -p")
    quit()

if not censys_query and not shodan_query:
    print("Provide Shodan search with -s and/or Censys query with -c")
    quit()

if shodan_query:
    shodan_key = getenv("SHODAN_API_KEY")
    shodan_api = Shodan(shodan_key)
    for result in shodan_api.search_cursor(shodan_query):
        ip = str(result["ip_str"])
        port = str(result["port"])
        url = f"http://{ip}:{port}"
        url_tls = f"https://{ip}:{port}"
        endpoints.add(url)
        endpoints.add(url_tls)
        domains = result["hostnames"]
        if len(domains) > 0:
            for domain in domains:
                url = f"http://{domain}:{port}"
                url_tls = f"https://{domain}:{port}"
                endpoints.add(url)
                endpoints.add(url_tls)

if censys_query:
    censys_api_id = getenv("CENSYS_API_ID")
    censys_api_secret = getenv("CENSYS_API_SECRET")
    censys_api = CensysHosts(censys_api_id, censys_api_secret)
    #censys_query = "ip:8.8.8.8 or ip:8.8.4.4"
    censys_search = censys_api.search(censys_query)
    try:
        censys_results = censys_search.view_all()
    except censys.common.exceptions.CensysRateLimitExceededException:
        print(f"{Fore.RED}[CENSYS]{Fore.RESET} Reached API Quota")
        censys_results = None
    if censys_results is not None:
        for ip in censys_results:
            ip_info = censys_results[ip]
            services = ip_info["services"]
            for service in services:
                service_name = service["extended_service_name"]
                service_port = service["port"]
                if service_name in [ "HTTP", "HTTPS" ]:
                    endpoint = str(service_name.lower() + "://" + ip + ":" + str(service_port))
                    endpoints.add(endpoint)

f = open(pattern_file, "r")
patterns = f.readlines()
f.close()

try:
    makedirs("downloads")
except FileExistsError:
    pass
chdir("downloads")

for endpoint in endpoints:
    print(f"{Fore.BLUE}[INFRASPYDER]{Fore.RESET} Checking {endpoint}")
    try:
        requests.get(endpoint, verify=False, timeout=5)
    except:
        continue
    dir_name = str(endpoint).replace(".", "_").replace(":", "_").replace("/", "_")
    try:
        makedirs(dir_name)
    except FileExistsError:
        pass
    chdir(dir_name)
    # Write log file for parsing
    # TO DO: Convert this to a proper spider
    wget_log = open("wget.log", "w")
    cmd = f"wget -t 1 --spider --no-parent --recursive --no-directories {endpoint}"
    cmd_array = cmd.split(" ")
    print(f"{Fore.CYAN}[INFRASPYDER]{Fore.RESET} Spidering {endpoint}".strip())
    sp.call(["wget", "-t", "1", "--spider", "--no-parent", "--recursive", "--no-directories", str(endpoint)], stderr=wget_log)
    wget_log.close()
    try:
        f = open("wget.log", "r")
    except FileNotFoundError:
        chdir("../")
        continue
    f.close()
    for pattern in patterns:
        cmd = "cat wget.log | grep http | grep " + pattern.strip() + " | sed 's/.* http/http/g' >> findings.log && sort -ufo findings.log findings.log"
        cmd_array = cmd.split(" ")
        system(cmd)
    try:
        f = open("findings.log", "r")
    except FileNotFoundError:
        chdir("../")
        continue
    findings = f.readlines()
    f.close()
    try:
        makedirs("findings")
    except FileExistsError:
        pass
    chdir("findings")
    for finding in findings:
        if finding.strip().endswith("/"):
            continue
        #print(f"Downloading {finding}".strip())
        cmd = f"wget -q -t 1 {finding}"
        cmd_array = cmd.split(" ")
        print(str(f"{Fore.BLUE}[INFRASPYDER]{Fore.RESET} Attempting to download {finding}").strip())
        download_log = ".tmp.log"
        try:
            remove(download_log)
        except FileNotFoundError:
            pass
        download_output = open(download_log, "w")
        sp.call(["wget", "-t", "5", str(finding).strip()], stderr=download_output)
        download_output.close()
        with open(download_log) as f:
            if "200 OK" in f.read():
                print(f"{Fore.GREEN}[INFRASPYDER]{Fore.RESET} File Downloaded")
            else:
                print(f"{Fore.RED}[INFRASPYDER]{Fore.RESET} Download Failed")
        remove(download_log)
    chdir("../../")
