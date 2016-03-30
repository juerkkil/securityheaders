# securityheaders
Python script to check HTTP security headers

Same functionality as securityheaders.io but as Python script. Also checks some server/version headers.

With minor modifications could be used as a library for other projects.

### Usage
```
$ python securityheaders.py --help
usage: securityheaders.py [-h] [--max-redirects N] URL

Check HTTP security headers

positional arguments:
  URL                Target URL

optional arguments:
  -h, --help         show this help message and exit
  --max-redirects N  Max redirects, set 0 to disable (default: 2)
$
```

### Output
```
$ python securityheaders.py http://www.secfault.fi
WARNING! Header 'x-xss-protection' is missing!
WARNING! Header 'x-content-type-options' is missing!
WARNING! Header 'content-security-policy' is missing!
WARNING! Header 'server' contains value nginx/1.8.1
$
```
