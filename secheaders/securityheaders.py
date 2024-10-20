import argparse
import http.client
import re
import socket
import ssl
import sys
from urllib.parse import ParseResult, urlparse

from . import utils
from .constants import DEFAULT_TIMEOUT, DEFAULT_URL_SCHEME, EVAL_WARN, REQUEST_HEADERS, HEADER_STRUCTURED_LIST, \
        SERVER_VERSION_HEADERS, HEADER_OUTPUT_MAX_LEN
from .exceptions import SecurityHeadersException, InvalidTargetURL, UnableToConnect


class SecurityHeaders():
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

    def __init__(self, url, max_redirects=2, insecure=False):
        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            url = f"{DEFAULT_URL_SCHEME}://{url}"
            parsed = urlparse(url)
            if not parsed.scheme and not parsed.netloc:
                raise InvalidTargetURL("Unable to parse the URL")

        self.protocol_scheme = parsed.scheme
        self.hostname = parsed.netloc
        self.path = parsed.path
        self.verify_ssl = not insecure
        self.target_url: ParseResult = self._follow_redirect_until_response(url, max_redirects) if max_redirects > 0 \
            else parsed
        self.headers = {}

    def test_https(self):
        redirect_supported = self._test_http_to_https()

        conn = http.client.HTTPSConnection(self.hostname, context=ssl.create_default_context(),
                                           timeout=DEFAULT_TIMEOUT)
        try:
            conn.request('GET', '/')
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            return {'supported': False, 'certvalid': False, 'redirect': redirect_supported}
        except ssl.SSLError:
            return {'supported': True, 'certvalid': False, 'redirect': redirect_supported}

        return {'supported': True, 'certvalid': True, 'redirect': redirect_supported}

    def _follow_redirect_until_response(self, url, follow_redirects=5):
        temp_url = urlparse(url)
        while follow_redirects >= 0:

            if temp_url.scheme == 'http':
                conn = http.client.HTTPConnection(temp_url.netloc, timeout=DEFAULT_TIMEOUT)
            elif temp_url.scheme == 'https':
                ctx = ssl.create_default_context() if self.verify_ssl else ssl._create_stdlib_context()  # pylint: disable=protected-access
                conn = http.client.HTTPSConnection(temp_url.netloc, context=ctx, timeout=DEFAULT_TIMEOUT)
            else:
                raise InvalidTargetURL("Unsupported protocol scheme")

            try:
                conn.request('GET', temp_url.path, headers=REQUEST_HEADERS)
                res = conn.getresponse()
            except (socket.gaierror, socket.timeout, ConnectionRefusedError, UnicodeError) as e:
                raise UnableToConnect(f"Connection failed {temp_url.netloc}") from e
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

    def _test_http_to_https(self, follow_redirects=5):
        url = f"http://{self.hostname}{self.path}"
        target_url = self._follow_redirect_until_response(url, follow_redirects)
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
                ctx = ssl._create_stdlib_context()  # pylint: disable=protected-access
            conn = http.client.HTTPSConnection(target_url.hostname, context=ctx, timeout=DEFAULT_TIMEOUT)
        else:
            raise InvalidTargetURL("Unsupported protocol scheme")

        return conn

    def fetch_headers(self):
        """ Fetch headers from the target site and store them into the class instance """

        conn = self.open_connection(self.target_url)
        try:
            conn.request('GET', self.target_url.path, headers=REQUEST_HEADERS)
            res = conn.getresponse()
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError, UnicodeError) as e:
            raise UnableToConnect(f"Connection failed {self.target_url.hostname}") from e

        headers = res.getheaders()
        for h in headers:
            key = h[0].lower()
            if key in HEADER_STRUCTURED_LIST and key in self.headers:
                # Scenario described in RFC 2616 section 4.2
                self.headers[key] += f', {h[1]}'
            else:
                self.headers[key] = h[1]

    def check_headers(self):
        """ Default return array """
        retval = {}

        if not self.headers:
            raise SecurityHeadersException("Headers not fetched successfully")

        for header, settings in self.SECURITY_HEADERS_DICT.items():
            if header in self.headers:
                eval_func = settings.get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException(f"No evaluation function found for header: {header}")
                res, notes = eval_func(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }
            else:
                warn = settings.get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

        for header in SERVER_VERSION_HEADERS:
            if header in self.headers:
                res, notes = utils.eval_version_info(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

        return retval

def output_cli(headers, https, verbose=False):
    for header, value in headers.items():
        output_str = ""
        if not value['defined']:
            output_str = f"Header '{header}' is missing"
        else:
            header_contents = value['contents']
            if not verbose and len(header_contents) > HEADER_OUTPUT_MAX_LEN:
                header_contents = f"{header_contents[0:HEADER_OUTPUT_MAX_LEN]}... (truncated)"

            output_str = f"{header}: {header_contents}"
        notes = ""
        for note in value['notes']:
            notes = f"{notes} * {note}\n"

        print_func = utils.print_warning if value['warn'] else utils.print_ok
        print_func(output_str)
        if notes:
            print(notes)

    msg_map = {
        'supported': 'HTTPS supported',
        'certvalid': 'HTTPS valid certificate',
        'redirect': 'HTTP -> HTTPS automatic redirect',
    }
    for key in https:
        if https[key]:
            utils.print_ok(msg_map[key])
        else:
            utils.print_warning(msg_map[key])


def main():
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    parser.add_argument('--insecure', dest='insecure', action='store_true',
                        help='Do not verify TLS certificate chain')
    parser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                        help='Verbose output')
    args = parser.parse_args()
    try:
        header_check = SecurityHeaders(args.url, args.max_redirects, args.insecure)
        header_check.fetch_headers()
        headers = header_check.check_headers()
    except SecurityHeadersException as e:
        print(e)
        sys.exit(1)

    if not headers:
        print("Failed to fetch headers, exiting...")
        sys.exit(1)

    https = header_check.test_https()
    output_cli(headers, https, args.verbose)

if __name__ == "__main__":
    main()
