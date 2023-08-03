import binascii
import json
from authlib.common.encoding import urlsafe_b64decode


def prepare_algorithm_key(algorithms, header, payload, key, private=False):
    algorithm = algorithms[header['alg']]
    if callable(key):
        key = key(header, payload)

    # apply `fix: CVE-2022-39175` on v0.11
    # https://github.com/lepture/authlib/commit/80b0808263c6ce88335532b78e62bf2522593390#diff-df89b0e3a859f7fe754890047b62a0e63a324b519316c6632125fd9c92b11a2e
    elif key is None and "jwk" in header:
        key = header["jwk"]

    if private:
        key = algorithm.prepare_private_key(key)
    else:
        key = algorithm.prepare_public_key(key)
    return algorithm, key


def extract_header(header_segment, error_cls):
    header_data = extract_segment(header_segment, error_cls, 'header')

    try:
        header = json.loads(header_data.decode('utf-8'))
    except ValueError as e:
        raise error_cls('Invalid header string: {}'.format(e))

    if not isinstance(header, dict):
        raise error_cls('Header must be a json object')
    return header


def extract_segment(segment, error_cls, name='payload'):
    try:
        return urlsafe_b64decode(segment)
    except (TypeError, binascii.Error):
        msg = 'Invalid {} padding'.format(name)
        raise error_cls(msg)
