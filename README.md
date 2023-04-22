# InfraSpyder

Automatically spider the result set of a Censys/Shodan search and download all files where the file name or folder path matches a regex.

## Usage

- Store Censys API credentials in environment variables, CENSYS_API_ID & CENSYS_API_SECRET
- Store Shodan API key in environment variable called SHODAN_API_KEY


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

## Tips

- The repo ships with a default `patterns.txt` that can be used to download all files
- The regexes in the patterns file are interpreted by `grep` (not extended regex patterns)
- Both a Shodan and Censys query can be supplied at the same time: `python3 infraspider.py -c '(Directory listing for ps)' -s "http.title:'Directory listing for' http.html:ps" -p patterns.txt`
