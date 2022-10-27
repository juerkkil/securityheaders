import re

from constants import EVAL_WARN, EVAL_OK


def eval_x_frame_options(contents: str) -> int:
    if contents.lower() in ['deny', 'sameorigin']:
        return EVAL_OK

    return EVAL_WARN


def eval_content_type_options(contents: str) -> int:
    if contents.lower() == 'nosniff':
        return EVAL_OK

    return EVAL_WARN


def eval_x_xss_protection(contents: str) -> int:
    # This header is deprecated but still used quite a lot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    if contents.lower() in ['1; mode=block', '0']:
        return EVAL_OK

    return EVAL_WARN


def eval_sts(contents: str) -> int:
    if re.match("^max-age=[0-9]+\\s*(;|$)\\s*", contents.lower()):
        return EVAL_OK

    return EVAL_WARN


def eval_csp(contents: str) -> int:
    # TODO! Evaluate that CSP is valid and secure
    return EVAL_OK


def eval_version_info(contents: str) -> int:
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 3 and re.match(".*[^0-9]+.*\\d.*", contents):
        return EVAL_WARN

    return EVAL_OK


def eval_permissions_policy(contents: str) -> int:
    # TODO! Evaluate Permission-Policy and ensure it's somewhat reasonable
    return EVAL_OK


def eval_referrer_policy(contents: str) -> int:
    if contents.lower() in [
        'no-referrer',
        'no-referrer-when-downgrade',
        'origin',
        'origin-when-cross-origin',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
    ]:
        return EVAL_OK

    return EVAL_WARN
