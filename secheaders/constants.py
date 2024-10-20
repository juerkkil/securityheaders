# If no URL scheme defined, what to use by default
DEFAULT_URL_SCHEME = 'https'
DEFAULT_TIMEOUT = 10

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

EVAL_WARN = 0
EVAL_OK = 1
OK_COLOR = '\033[92m'
END_COLOR = '\033[0m'
WARN_COLOR = '\033[93m'
HEADER_OUTPUT_MAX_LEN = 40  # longer response headers are truncated in cli output, unless -v flag used

# There are no universal rules for "safe" and "unsafe" CSP directives, but we apply some common sense here to
# catch some risky configurations
UNSAFE_CSP_RULES = {
    "script-src": ["*", "'unsafe-eval'", "data:", "'unsafe-inline'", "http:"],
    "frame-ancestors": ["*"],
    "form-action": ["*"],
    "object-src": ["*"],
}

# Configuring Permission-Policy is very case-specific and it's difficult to define a particular recommendation.
# We apply here a logic, that access to privacy-sensitive features and payments API should be restricted.
RESTRICTED_PERM_POLICY_FEATURES = ['camera', 'geolocation', 'microphone', 'payment']

# Headers that we try to sniff for version information
SERVER_VERSION_HEADERS = [
    'x-powered-by',
    'server',
    'x-aspnet-version',
]

HEADER_STRUCTURED_LIST = [  # Response headers that define multiple values as comma-sparated list
    'permissions-policy',
]
