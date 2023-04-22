# InfraSpyder

Automatically spider the result set of a Censys/Shodan search and download all files where the file name or folder path matches a regex.

*This is basically a wrapper around various Linux binaries*

## Usage

- Intended for open directory hunting, may have unkown bugs if used for any other type of web site
- Store Censys API credentials in environment variables, CENSYS_API_ID & CENSYS_API_SECRET
- Store Shodan API key in environment variable called SHODAN_API_KEY
- All files downloaded can be found in the `findings` folder of the respective host listed in the `downloads` folder (e.g. `downloads/protocol_hostname_port/findings/`)
- This must be ran on Linux (uses `grep`, `sort`, `wget`, etc.)
- Tries HTTP and HTTPS on all IP/port combos found

```
Automatically spider the result set of a Censys/Shodan search and download all files where the file name or folder path matches a regex.

optional arguments:
  -h, --help            show this help message and exit
  -c CENSYS_QUERY, --censys-query CENSYS_QUERY
                        Censys Query
  -s SHODAN_QUERY, --shodan-query SHODAN_QUERY
                        Shodan Query
  -p PATTERNS, --patterns PATTERNS
                        File containing patterns to match (POSIX regex)
```

### Examples

- Search Shodan Only: `python3 infraspider.py -s "http.title:'Directory listing for' http.html:ps" -p patterns.txt`
- Search Censys Only: `python3 infraspider.py -c '(Directory listing for ps)' -p patterns.txt`
- Search Both Censys and Shodan: `python3 infraspider.py -c '(Directory listing for ps)' -s "http.title:'Directory listing for' http.html:ps" -p patterns.txt`

## Tips

- The repo ships with a default `patterns.txt` that can be used to download all files
- The regexes in the patterns file are interpreted by `grep` (not extended regex patterns)
- Sometimes the spidering phase (marked in Light Blue/Cyan in the output) will take a long time