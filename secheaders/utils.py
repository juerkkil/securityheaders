import re
from typing import Tuple

from .constants import EVAL_WARN, EVAL_OK, UNSAFE_CSP_RULES, RESTRICTED_PERM_POLICY_FEATURES, WARN_COLOR, OK_COLOR, \
    END_COLOR


def eval_x_frame_options(contents: str) -> Tuple[int, list]:
    if contents.lower() in ['deny', 'sameorigin']:
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_content_type_options(contents: str) -> Tuple[int, list]:
    if contents.lower() == 'nosniff':
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_x_xss_protection(contents: str) -> Tuple[int, list]:
    # This header is deprecated but still used quite a lot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    if contents.lower() in ['1; mode=block', '0']:
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_sts(contents: str) -> Tuple[int, list]:
    if re.match("^max-age=[0-9]+\\s*(;|$)\\s*", contents.lower()):
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_csp(contents: str) -> Tuple[int, list]:
    csp_unsafe = False
    csp_notes = []

    csp_parsed = csp_parser(contents)

    for rule, values in UNSAFE_CSP_RULES.items():
        if rule not in csp_parsed:
            if '-src' in rule and 'default-src' in csp_parsed:
                # fallback to default-src
                for unsafe_src in values:
                    if unsafe_src in csp_parsed['default-src']:
                        csp_unsafe = True
                        csp_notes.append(
                            f"Directive {rule} not defined, and default-src contains unsafe source {unsafe_src}"
                        )
            elif 'default-src' not in csp_parsed:
                csp_notes.append(f"No directive {rule} nor default-src defined in the Content Security Policy")
                csp_unsafe = True
        else:
            for unsafe_src in values:
                if unsafe_src in csp_parsed[rule]:
                    csp_notes.append(f"Unsafe source {unsafe_src} in directive {rule}")
                    csp_unsafe = True

    if csp_unsafe:
        return EVAL_WARN, csp_notes

    return EVAL_OK, []


def eval_version_info(contents: str) -> Tuple[int, list]:
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 3 and re.match(".*[^0-9]+.*\\d.*", contents):
        return EVAL_WARN, []

    return EVAL_OK, []


def eval_permissions_policy(contents: str) -> Tuple[int, list]:
    pp_parsed = permissions_policy_parser(contents)
    notes = []
    pp_unsafe = False

    for feature in RESTRICTED_PERM_POLICY_FEATURES:
        feat_policy = pp_parsed.get(feature)
        if feat_policy is None:
            pp_unsafe = True
            notes.append(f"Privacy-sensitive feature '{feature}' not defined in permission-policy, always allowed.")
        elif '*' in feat_policy:
            pp_unsafe = True
            notes.append(f"Privacy-sensitive feature '{feature}' allowed from unsafe origin '*'")
    if pp_unsafe:
        return EVAL_WARN, notes

    return EVAL_OK, []


def eval_referrer_policy(contents: str) -> Tuple[int, list]:
    if contents.lower().strip() in [
        'no-referrer',
        'no-referrer-when-downgrade',
        'origin',
        'origin-when-cross-origin',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
    ]:
        return EVAL_OK, []

    return EVAL_WARN, [f"Unsafe contents: {contents}"]


def csp_parser(contents: str) -> dict:
    csp = {}
    directives = contents.split(";")
    for directive in directives:
        directive = directive.strip().split()
        if directive:
            csp[directive[0]] = directive[1:] if len(directive) > 1 else []

    return csp


def permissions_policy_parser(contents: str) -> dict:
    policies = contents.split(",")
    retval = {}
    for policy in policies:
        match = re.match('^(\\w+(?:-\\w+)*)=(\\(([^\\)]*)\\)|\\*|self);?$', policy.strip())
        if match:
            feature = match.groups()[0]
            feature_policy = match.groups()[2] if match.groups()[2] is not None else match.groups()[1]
            retval[feature] = feature_policy.split()

    return retval


def print_ok(msg: str):
    print(f"{msg}  [ {OK_COLOR}OK{END_COLOR} ]")


def print_warning(msg: str):
    print(f"{msg} [ {WARN_COLOR}WARN{END_COLOR} ]")
