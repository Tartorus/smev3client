import uuid
from suds.client import Client

from smev3.exceptions import SmevClientError
from smev3.plugins import ContentPlugin, UPRIDPlugin, SignPlugin


class BaseSmev3Client(Client):

    SMEV_EXEC_URL = 'http://smev3-d.test.gosuslugi.ru:7500/ws?wsdl'
    PRIVATE_KEY_FILE = ''
    PASSWORD = None
    CERTIFICATE_FILE = ''

    def __init__(self, content_plugin):
        plugins = [SignPlugin(cert_path=self.CERTIFICATE_FILE,
                              pkey_path=self.PRIVATE_KEY_FILE,
                              pkey_password=self.PASSWORD)]

        if content_plugin:
            if not isinstance(content_plugin, ContentPlugin):
                raise SmevClientError('Content plugin is not instance of ContentPlugin')
            plugins.append(content_plugin)

        super().__init__(self.SMEV_EXEC_URL, plugins=plugins)

    def send_request(self):
        request_data = self.sender_provided_request_data()
        return self.service.SendRequest(request_data)

    def sender_provided_request_data(self):
        request_data = self.factory.create('ns0:SenderProvidedRequestData')
        request_data.MessageID = str(uuid.uuid1())
        return request_data
