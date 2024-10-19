class SecurityHeadersException(Exception):
    pass


class InvalidTargetURL(SecurityHeadersException):
    pass


class UnableToConnect(SecurityHeadersException):
    pass
