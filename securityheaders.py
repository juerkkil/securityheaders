import argparse
import http.client
import re
import socket
import ssl
import sys
from urllib.parse import ParseResult, urlparse

import utils
from constants import DEFAULT_TIMEOUT, DEFAULT_URL_SCHEME, EVAL_WARN


class SecurityHeadersException(Exception):
    pass


class InvalidTargetURL(SecurityHeadersException):
    pass


class UnableToConnect(SecurityHeadersException):
    pass


class SecurityHeaders():
    # Let's try to imitate a legit browser to avoid being blocked / flagged as web crawler
    REQUEST_HEADERS = {
        'Accept': ('text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                   'application/signed-exchange;v=b3;q=0.9'),
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-GB,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                       'Chrome/106.0.0.0 Safari/537.36'),
    }

    SECURITY_HEADERS_DICT = {
        'x-frame-options': {
            'recommended': True,
            'eval_func': utils.eval_x_frame_options,
        },
        'strict-transport-security': {
            'recommended': True,
            'eval_func': utils.eval_sts,
        },
        'content-security-policy': {
            'recommended': True,
            'eval_func': utils.eval_csp,
        },
        'x-content-type-options': {
            'recommended': True,
            'eval_func': utils.eval_content_type_options,
        },
        'x-xss-protection': {
            # X-XSS-Protection is deprecated; not supported anymore, and may be even dangerous in older browsers
            'recommended': False,
            'eval_func': utils.eval_x_xss_protection,
        },
        'referrer-policy': {
            'recommended': True,
            'eval_func': utils.eval_referrer_policy,
        },
        'permissions-policy': {
            'recommended': True,
            'eval_func': utils.eval_permissions_policy,
        }
    }

    SERVER_VERSION_HEADERS = [
        'x-powered-by',
        'server',
        'x-aspnet-version',
    ]

    HEADER_STRUCTURED_LIST = [  # Response headers that define multiple values as comma-sparated list
        'permissions-policy',
    ]

    def __init__(self, url, max_redirects=2, no_check_certificate=False):
        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            url = "{}://{}".format(DEFAULT_URL_SCHEME, url)
            parsed = urlparse(url)
            if not parsed.scheme and not parsed.netloc:
                raise InvalidTargetURL("Unable to parse the URL")

        self.protocol_scheme = parsed.scheme
        self.hostname = parsed.netloc
        self.path = parsed.path
        self.verify_ssl = False if no_check_certificate else True
        self.target_url: ParseResult = self._follow_redirect_until_response(url, max_redirects) if max_redirects > 0 \
            else parsed
        self.headers = {}

    def test_https(self):
        conn = http.client.HTTPSConnection(self.hostname, context=ssl.create_default_context(),
                                           timeout=DEFAULT_TIMEOUT)
        try:
            conn.request('GET', '/')
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            return {'supported': False, 'certvalid': False}
        except ssl.SSLError:
            return {'supported': True, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def _follow_redirect_until_response(self, url, follow_redirects=5):
        temp_url = urlparse(url)
        while follow_redirects >= 0:

            if temp_url.scheme == 'http':
                conn = http.client.HTTPConnection(temp_url.netloc, timeout=DEFAULT_TIMEOUT)
            elif temp_url.scheme == 'https':
                ctx = ssl.create_default_context() if self.verify_ssl else ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(temp_url.netloc, context=ctx, timeout=DEFAULT_TIMEOUT)
            else:
                raise InvalidTargetURL("Unsupported protocol scheme")

            try:
                conn.request('GET', temp_url.path, headers=self.REQUEST_HEADERS)
                res = conn.getresponse()
            except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
                raise UnableToConnect("Connection failed {}".format(temp_url.netloc)) from e
            except ssl.SSLError as e:
                raise UnableToConnect("SSL Error") from e

            if res.status >= 300 and res.status < 400:
                headers = res.getheaders()
                headers_dict = {x[0].lower(): x[1] for x in headers}
                if 'location' in headers_dict:
                    if re.match("^https?://", headers_dict['location']):
                        temp_url = urlparse(headers_dict['location'])
                    else:  # Probably relative path
                        temp_url = temp_url._replace(path=headers_dict['location'])
            else:
                return temp_url

            follow_redirects -= 1

        # More than x redirects, stop here
        return temp_url

    def test_http_to_https(self, follow_redirects=5):
        url = "http://{}{}".format(self.hostname, self.path)
        target_url = self._follow_redirect_until_response(url)
        if target_url and target_url.scheme == 'https':
            return True

        return False

    def open_connection(self, target_url):
        if target_url.scheme == 'http':
            conn = http.client.HTTPConnection(target_url.hostname, timeout=DEFAULT_TIMEOUT)
        elif target_url.scheme == 'https':
            if self.verify_ssl:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl._create_stdlib_context()
            conn = http.client.HTTPSConnection(target_url.hostname, context=ctx, timeout=DEFAULT_TIMEOUT)
        else:
            raise InvalidTargetURL("Unsupported protocol scheme")

        return conn

    def fetch_headers(self):
        """ Fetch headers from the target site and store them into the class instance """

        conn = self.open_connection(self.target_url)
        try:
            conn.request('GET', self.target_url.path, headers=self.REQUEST_HEADERS)
            res = conn.getresponse()
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            raise UnableToConnect("Connection failed {}".format(self.target_url.hostname)) from e

        headers = res.getheaders()
        for h in headers:
            key = h[0].lower()
            if key in self.HEADER_STRUCTURED_LIST and key in self.headers:
                # Scenario described in RFC 2616 section 4.2
                self.headers[key] += ', {}'.format(h[1])
            else:
                self.headers[key] = h[1]

    def check_headers(self):
        """ Default return array """
        retval = {}

        if not self.headers:
            raise SecurityHeadersException("Headers not fetched successfully")

        """ Loop through headers and evaluate the risk """
        for header in self.SECURITY_HEADERS_DICT:
            if header in self.headers:
                eval_func = self.SECURITY_HEADERS_DICT[header].get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException("No evaluation function found for header: {}".format(header))
                res, notes = eval_func(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

            else:
                warn = self.SECURITY_HEADERS_DICT[header].get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

        for header in self.SERVER_VERSION_HEADERS:
            if header in self.headers:
                res, notes = utils.eval_version_info(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

        return retval


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    parser.add_argument('--no-check-certificate', dest='no_check_certificate', action='store_true',
                        help='Do not verify TLS certificate chain')
    args = parser.parse_args()
    try:
        header_check = SecurityHeaders(args.url, args.max_redirects, args.no_check_certificate)
        header_check.fetch_headers()
        headers = header_check.check_headers()
    except SecurityHeadersException as e:
        print(e)
        sys.exit(1)

    if not headers:
        print("Failed to fetch headers, exiting...")
        sys.exit(1)

    for header, value in headers.items():
        if value['warn']:
            if not value['defined']:
                utils.print_warning("Header '{}' is missing".format(header))
            else:
                utils.print_warning("Header '{}' contains value '{}".format(header, value['contents']))
                for n in value['notes']:
                    print(" * {}".format(n))
        else:
            if not value['defined']:
                utils.print_ok("Header '{}' is missing".format(header))
            else:
                utils.print_ok("Header '{}' contains a proper value".format(header))

    https = header_check.test_https()
    if https['supported']:
        utils.print_ok("HTTPS supported")
    else:
        utils.print_warning("HTTPS supported")

    if https['certvalid']:
        utils.print_ok("HTTPS valid certificate")
    else:
        utils.print_warning("HTTPS valid certificate")

    if header_check.test_http_to_https():
        utils.print_ok("HTTP -> HTTPS redirect")
    else:
        utils.print_warning("HTTP -> HTTPS redirect")
