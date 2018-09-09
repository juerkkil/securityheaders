import http.client
import argparse
import socket 
import ssl
import sys
import re

from urllib.parse import urlparse

class SecurityHeaders():
    def __init__(self):
        pass

    def evaluate_warn(self, header, contents):
        """ Risk evaluation function.
        Set header warning flag (1/0) according to its contents.
        Args:
            header (str): HTTP header name in lower-case
            contents (str): Header contents (value)
        """
        warn = 1

        if header == 'x-frame-options':
            if contents.lower() in ['deny', 'sameorigin']:
                warn = 0
            else:
                warn = 1

        if header == 'strict-transport-security':
            warn = 0

        """ Evaluating the warn of CSP contents may be a bit more tricky.
            For now, just disable the warn if the header is defined
            """
        if header == 'content-security-policy':
            warn = 0

        """ Raise the warn flag, if cross domain requests are allowed from any 
            origin """
        if header == 'access-control-allow-origin':
            if contents == '*':
                warn = 1
            else:
                warn = 0
    
        if header.lower() == 'x-xss-protection':
            if contents.lower() in ['1', '1; mode=block']:
                warn = 0
            else:
                warn = 1

        if header == 'x-content-type-options':
            if contents.lower() == 'nosniff':
                warn = 0
            else:
                warn =1

        """ Enable warning if backend version information is disclosed """
        if header == 'x-powered-by' or header == 'server':
            if len(contents) > 1:
                warn = 1
            else: 
                warn = 0

        return {'defined': True, 'warn': warn, 'contents': contents}

    def test_https(self, url):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        sslerror = False
            
        conn = http.client.HTTPSConnection(hostname, context = ssl.create_default_context() )
        try:
            conn.request('GET', '/')
            res = conn.getresponse()
        except socket.gaierror:
            return {'supported': False, 'certvalid': False}
        except ssl.CertificateError:
            return {'supported': True, 'certvalid': False}
        except:
            sslerror = True

        # if tls connection fails for unexcepted error, retry without verifying cert
        if sslerror:
            conn = http.client.HTTPSConnection(hostname, timeout=5, context = ssl._create_stdlib_context() )
            try:
                conn.request('GET', '/')
                res = conn.getresponse()
                return {'supported': True, 'certvalid': False}
            except:
                return {'supported': False, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def test_http_to_https(self, url, follow_redirects = 5):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if not protocol:
            protocol = 'http' # default to http if protocl scheme not specified

        if protocol == 'https' and follow_redirects != 5:
            return True
        elif protocol == 'https' and follow_redirects == 5:
            protocol = 'http'

        if (protocol == 'http'):
            conn = http.client.HTTPConnection(hostname)
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print('HTTP request failed')
            return False

        """ Follow redirect """
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0].lower() == 'location'):
                    return self.test_http_to_https(header[1], follow_redirects - 1) 

        return False

    def check_headers(self, url, follow_redirects = 0):
        """ Make the HTTP request and check if any of the pre-defined
        headers exists.
        Args:
            url (str): Target URL in format: scheme://hostname/path/to/file
            follow_redirects (Optional[str]): How deep we follow the redirects, 
            value 0 disables redirects.
        """

        """ Default return array """
        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''}, 
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''} 
        }

        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if (protocol == 'http'):
            conn = http.client.HTTPConnection(hostname)
        elif (protocol == 'https'):
                # on error, retry without verifying cert
                # in this context, we're not really interested in cert validity
                ctx = ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(hostname, context = ctx )
        else:
            """ Unknown protocol scheme """
            return {}
    
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
            
        except socket.gaierror:
            print('HTTP request failed')
            return False

        """ Follow redirect """
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0].lower() == 'location'):
                    redirect_url = header[1]
                    if not re.match('^https?://', redirect_url):
                        redirect_url = protocol + '://' + hostname + redirect_url
                    return self.check_headers(redirect_url, follow_redirects - 1) 
                
        """ Loop through headers and evaluate the risk """
        for header in headers:

            #set to lowercase before the check
            headerAct = header[0].lower()

            if (headerAct in retval):
                retval[headerAct] = self.evaluate_warn(headerAct, header[1])

        return retval

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Check HTTP security headers', \
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int, help='Max redirects, set 0 to disable')
    args = parser.parse_args()
    url = args.url


    redirects = args.max_redirects

    foo = SecurityHeaders()

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url # default to http if scheme not provided


    headers = foo.check_headers(url, redirects)

    if not headers:
        print ("Failed to fetch headers, exiting...")
        sys.exit(1)

    okColor = '\033[92m'
    warnColor = '\033[93m'
    endColor = '\033[0m'
    for header, value in headers.items():
        if value['warn'] == 1:
            if value['defined'] == False:
                print('Header \'' + header + '\' is missing ... [ ' + warnColor + 'WARN' + endColor + ' ]')
            else:
                print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                    ' ... [ ' + warnColor + 'WARN' + endColor + ' ]')
        elif value['warn'] == 0:
            if value['defined'] == False:
                print('Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]')
            else:
                print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                    ' ... [ ' + okColor + 'OK' + endColor + ' ]')

    https = foo.test_https(url)
    if https['supported']:
        print('HTTPS supported ... [ ' + okColor + 'OK' + endColor + ' ]')
    else:
        print('HTTPS supported ... [ ' + warnColor + 'FAIL' + endColor + ' ]')

    if https['certvalid']:
        print('HTTPS valid certificate ... [ ' + okColor + 'OK' + endColor + ' ]')
    else:
        print('HTTPS valid certificate ... [ ' + warnColor + 'FAIL' + endColor + ' ]')


    if foo.test_http_to_https(url, 5):
        print('HTTP -> HTTPS redirect ... [ ' + okColor + 'OK' + endColor + ' ]')
    else:
        print('HTTP -> HTTPS redirect ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
