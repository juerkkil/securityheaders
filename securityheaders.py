import argparse
import http.client
import socket
import ssl
import sys
from urllib.parse import urlparse

DEFAULT_URL_SCHEME = 'https'


class SecurityHeaders():

    def __init__(self, url, max_redirects=2):
        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            url = "{}://{}".format(DEFAULT_URL_SCHEME, url)
            parsed = urlparse(url)
            if not parsed.scheme and not parsed.netloc:
                raise Exception("Incorrect URL")

        self.protocol_scheme = parsed.scheme
        self.hostname = parsed.netloc
        self.path = parsed.path
        self.max_redirects = max_redirects
        self.headers = None

    def _evaluate_header_warning(self, header, contents):
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

    def test_https(self):
        sslerror = False

        conn = http.client.HTTPSConnection(self.hostname, context=ssl.create_default_context())
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
            conn = http.client.HTTPSConnection(self.hostname, timeout=5, context=ssl._create_stdlib_context())
            try:
                conn.request('GET', '/')
                conn.getresponse()
                return {'supported': True, 'certvalid': False}
            except:  # # noqa: E722
                return {'supported': False, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def _follow_redirect_until_response(self, url, follow_redirects=5):
        temp_url = urlparse(url)
        while follow_redirects >= 0:
            sslerror = False
            if not temp_url.netloc:
                raise Exception("Invalid redirect URL")

            if temp_url.scheme == 'http':
                conn = http.client.HTTPConnection(temp_url.netloc)
            elif temp_url.scheme == 'https':
                ctx = ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(temp_url.netloc, context=ctx)
            else:
                raise Exception("Unsupported protocol scheme")

            try:
                conn.request('HEAD', temp_url.path)
                res = conn.getresponse()
                if temp_url.scheme == 'https':
                    sslerror = False
            except socket.gaierror:
                return None
            except ssl.CertificateError:
                sslerror = True
            except:  # noqa: E722
                if temp_url.scheme == 'https':
                    # Possibly some random SSL error
                    sslerror = True
                else:
                    return None

            # If SSL error, retry without verifying the certificate chain
            if sslerror:
                conn = http.client.HTTPSConnection(self.hostname, timeout=5, context=ssl._create_stdlib_context())
                try:
                    conn.request('HEAD', temp_url.path)
                    res = conn.getresponse()
                except:  # # noqa: E722
                    # HTTPS Connection failed
                    return None

            if res.status >= 300 and res.status < 400:
                headers = res.getheaders()
                headers_dict = {x[0].lower(): x[1] for x in headers}
                if 'location' in headers_dict:
                    temp_url = urlparse(headers_dict['location'])
            else:
                return temp_url

            follow_redirects -= 1

        # More than x redirects, stop here
        return None

    def test_http_to_https(self, follow_redirects=5):
        url = "http://{}{}".format(self.hostname, self.path)
        target_url = self._follow_redirect_until_response(url)
        if target_url and target_url.scheme == 'https':
            return True

        return False

    def fetch_headers(self):
        """ Make the HTTP request and check if any of the pre-defined
        headers exists.
        """
        initial_url = "{}://{}{}".format(self.protocol_scheme, self.hostname, self.path)
        target_url = None
        if self.max_redirects:
            target_url = self._follow_redirect_until_response(initial_url, self.max_redirects)

        if not target_url:
            # If redirects lead to failing URL, fall back to the initial url
            target_url = urlparse(initial_url)

        if target_url.scheme == 'http':
            conn = http.client.HTTPConnection(target_url.hostname)
        elif target_url.scheme == 'https':
            # Don't verify certs here - we're interested in headers, HTTPS is checked separately
            ctx = ssl._create_stdlib_context()
            conn = http.client.HTTPSConnection(target_url.hostname, context=ctx)
        else:
            raise Exception("Unknown protocol scheme")

        try:
            conn.request('HEAD', target_url.path)
            res = conn.getresponse()
        except socket.gaierror:
            raise Exception("Connection failed")

        headers = res.getheaders()
        self.headers = {x[0].lower(): x[1] for x in headers}

    def check_headers(self):
        """ Default return array """
        retval = {
            'x-frame-options': {'defined': False, 'warn': True, 'contents': ''},
            'strict-transport-security': {'defined': False, 'warn': True, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': False, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': True, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': True, 'contents': ''},
            'x-content-type-options': {'defined': False, 'warn': True, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': False, 'contents': ''},
            'server': {'defined': False, 'warn': False, 'contents': ''},
        }

        if not self.headers:
            raise Exception("No headers found")
        """ Loop through headers and evaluate the risk """
        for header in retval:
            if header in self.headers:
                retval[header] = self._evaluate_header_warning(header, self.headers[header])

        return retval


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    args = parser.parse_args()
    header_check = SecurityHeaders(args.url, args.max_redirects)
    header_check.fetch_headers()
    headers = header_check.check_headers()
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
                print("Header '{}' contains value '{}'... [ {}WARN{} ]".format(
                    header, value['contents'], warn_color, end_color,
                ))
        else:
            if not value['defined']:
                print("Header '{}' is missing ... [ {}OK{} ]".format(header, ok_color, end_color))
            else:
                print("Header '{}' contains value '{}'... [ {}OK{} ]".format(
                    header, value['contents'], ok_color, end_color,
                ))

    https = header_check.test_https()
    if https['supported']:
        print("HTTPS supported ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS supported ... [ {}FAIL{} ]".format(warn_color, end_color))

    if https['certvalid']:
        print("HTTPS valid certificate ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS valid certificate ... [ {}FAIL{} ]".format(warn_color, end_color))

    if header_check.test_http_to_https():
        print("HTTP -> HTTPS redirect ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTP -> HTTPS redirect ... [ {}FAIL{} ]".format(warn_color, end_color))
