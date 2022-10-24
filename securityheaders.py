import argparse
import http.client
import re
import socket
import ssl
import sys
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
        warn = True

        if header == 'x-frame-options':
            if contents.lower() in ['deny', 'sameorigin']:
                warn = False
            else:
                warn = True

        if header == 'strict-transport-security':
            warn = False

        """ Evaluating the warn of CSP contents may be a bit more tricky.
            For now, just disable the warn if the header is defined
            """
        if header == 'content-security-policy':
            warn = False

        """ Raise the warn flag, if cross domain requests are allowed from any
            origin """
        if header == 'access-control-allow-origin':
            if contents == '*':
                warn = True
            else:
                warn = False

        if header.lower() == 'x-xss-protection':
            if contents.lower() in ['1', '1; mode=block']:
                warn = False
            else:
                warn = True

        if header == 'x-content-type-options':
            if contents.lower() == 'nosniff':
                warn = False
            else:
                warn = True

        """ Enable warning if backend version information is disclosed """
        if header == 'x-powered-by' or header == 'server':
            if len(contents) > 1:
                warn = True
            else:
                warn = False

        return {'defined': True, 'warn': warn, 'contents': contents}

    def test_https(self, url):
        parsed = urlparse(url)
        hostname = parsed[1]
        sslerror = False

        conn = http.client.HTTPSConnection(hostname, context=ssl.create_default_context())
        try:
            conn.request('GET', '/')
            conn.getresponse()
        except socket.gaierror:
            return {'supported': False, 'certvalid': False}
        except ssl.CertificateError:
            return {'supported': True, 'certvalid': False}
        except:  # # noqa: E722
            sslerror = True

        # if tls connection fails for unexcepted error, retry without verifying cert
        if sslerror:
            conn = http.client.HTTPSConnection(hostname, timeout=5, context=ssl._create_stdlib_context())
            try:
                conn.request('GET', '/')
                conn.getresponse()
                return {'supported': True, 'certvalid': False}
            except:  # # noqa: E722
                return {'supported': False, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def test_http_to_https(self, url, follow_redirects=5):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if not protocol:
            protocol = 'http'  # default to http if protocl scheme not specified

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
        if (res.status >= 300 and res.status < 400 and follow_redirects > 0):
            for header in headers:
                if (header[0].lower() == 'location'):
                    return self.test_http_to_https(header[1], follow_redirects - 1)

        return False

    def check_headers(self, url, follow_redirects=0):
        """ Make the HTTP request and check if any of the pre-defined
        headers exists.
        Args:
            url (str): Target URL in format: scheme://hostname/path/to/file
            follow_redirects (Optional[str]): How deep we follow the redirects,
            value 0 disables redirects.
        """

        """ Default return array """
        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': ''},
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''},
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''},
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
            conn = http.client.HTTPSConnection(hostname, context=ctx)
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
        if (res.status >= 300 and res.status < 400 and follow_redirects > 0):
            for header in headers:
                if (header[0].lower() == 'location'):
                    redirect_url = header[1]
                    if not re.match('^https?://', redirect_url):
                        redirect_url = protocol + '://' + hostname + redirect_url
                    return self.check_headers(redirect_url, follow_redirects - 1)

        """ Loop through headers and evaluate the risk """
        for header in headers:
            header_act = header[0].lower()
            if (header_act in retval):
                retval[header_act] = self.evaluate_warn(header_act, header[1])

        return retval


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    args = parser.parse_args()
    url = args.url

    redirects = args.max_redirects
    header_check = SecurityHeaders()

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url  # default to http if scheme not provided

    headers = header_check.check_headers(url, redirects)
    if not headers:
        print("Failed to fetch headers, exiting...")
        sys.exit(1)

    ok_color = '\033[92m'
    warn_color = '\033[93m'
    end_color = '\033[0m'
    for header, value in headers.items():
        if value['warn']:
            if not value['defined']:
                print("Header '{}' is missing ... [ {}WARN{} ]".format(header, warn_color, end_color))
            else:
                print("Header '{}' contains value '{}... [ {}WARN{} ]".format(
                    header, value['contents'], warn_color, end_color,
                ))
        else:
            if not value['defined']:
                print("Header '{}' is missing ... [ {}OK{} ]".format(header, ok_color, end_color))
            else:
                print("Header '{}' contains value '{}... [ {}OK{} ]".format(
                    header, value['contents'], ok_color, end_color,
                ))

    https = header_check.test_https(url)
    if https['supported']:
        print("HTTPS supported ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS supported ... [ {}FAIL{} ]".format(warn_color, end_color))

    if https['certvalid']:
        print("HTTPS valid certificate ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS valid certificate ... [ {}FAIL{} ]".format(warn_color, end_color))

    if header_check.test_http_to_https(url, 5):
        print("HTTP -> HTTPS redirect ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTP -> HTTPS redirect ... [ {}FAIL{} ]".format(warn_color, end_color))
