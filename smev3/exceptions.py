class SmevClientError(Exception):
    """Исключение смэв клиента"""
    pass


class PluginError(SmevClientError):
    pass


class CertificateError(Exception):
    """Исключение сертификата"""
