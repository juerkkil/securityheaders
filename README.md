# secheaders
Python script to check HTTP security headers


Same functionality as securityheaders.io but as Python script. Also checks some server/version headers. Written and tested using Python 3.4.

With minor modifications could be used as a library for other projects.

## Installation

The following assumes you have Python  installed and command `python` refers to python version >= 3.4.

### Run without installation

1. Clone into repository
2. Run `python -m secheaders`

### Installation

1. Clone into repository
2. `python -m build`
3. `pip install dist/secheaders-0.1.0-py3-none-any.whl`
4. Run `secheaders --help`



### Usage
```
$ secheaders --help
usage: secheaders [-h] [--max-redirects N] [--no-check-certificate] URL

Check HTTP security headers

positional arguments:
  URL                   Target URL

options:
  -h, --help            show this help message and exit
  --max-redirects N     Max redirects, set 0 to disable (default: 2)
  --no-check-certificate
                        Do not verify TLS certificate chain (default: False)
```


### Example output
```
$ secheaders example.com
Header 'x-frame-options' is missing ... [ WARN ]
Header 'strict-transport-security' is missing ... [ WARN ]
Header 'content-security-policy' is missing ... [ WARN ]
Header 'x-content-type-options' is missing ... [ WARN ]
Header 'x-xss-protection' is missing ... [ OK ]
Header 'referrer-policy' is missing ... [ WARN ]
Header 'permissions-policy' is missing ... [ WARN ]
Header 'server' contains value 'ECAcc (nyd/D187) ... [ WARN ]
HTTPS supported ... [ OK ]
HTTPS valid certificate ... [ OK ]
HTTP -> HTTPS redirect ... [ WARN ]
```

## Note

The project renamed (2024-10-19) from **securityheaders** to **secheaders** to avoid confusion with PyPI package with similar name.
