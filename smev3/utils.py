import re
import subprocess

from lxml import etree
from smev3.exceptions import CertificateError


CERTIFICATE_PEM_PATTERN = re.compile(
    rb'-----BEGIN CERTIFICATE-----(?P<data>[a-zA-Z0-9+/]+=*)-----END CERTIFICATE-----')


def load_certificate(cert_filename):

    with open(cert_filename, 'rb') as f:
        buffer = f.read()
        certificate_data = buffer.replace(b'\n', b'').replace(b'\r', b'')
        match = re.match(CERTIFICATE_PEM_PATTERN, certificate_data)
        if match is None:
            raise CertificateError('Unable to find certificate data in file')
        return match.groupdict()['data'].decode()


def encode_c14n(xml_doc):
    return etree.tostring(xml_doc, method='c14n', exclusive=True, with_comments=False)


def get_gost_r_34102001_signature(data, pkey_filename, passwd=None):
    args = ['dgst', '-sign', pkey_filename, '-binary', '-md_gost94']
    if passwd:
        if isinstance(passwd, str):
            passwd = passwd.encode('utf-8')
        args += ['-passin', 'stdin']
        data = passwd + b'\n' + data
    return run_openssl(args, data)


def get_gost_r_3410_digest(data):
    args = ['dgst', '-binary', '-md_gost94']
    return run_openssl(args, data)


def run_openssl(openssl_args, stdin, timeout=10):
    args = ['openssl'] + openssl_args
    popen = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    stdout, stderr = popen.communicate(input=stdin, timeout=timeout)
    if popen.returncode != 0:
        raise subprocess.CalledProcessError(popen.returncode, args, stderr.decode('utf-8'))
    return stdout
