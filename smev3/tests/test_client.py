from unittest import TestCase
from unittest.mock import patch

from smev3.client import BaseSmev3Client
from smev3.plugins import UPRIDPlugin, SignPlugin


class TestBaseSmev3Client(TestCase):

    @patch('smev3.plugins.uuid.uuid4', return_value='ab7fcb62-e725-11e8-9e70-509a4cba3fff')
    @patch('smev3.client.uuid.uuid1', return_value='ab7fcb62-e725-11e8-9e70-509a4cba3fff')
    def test(self, *mocks):
        plugin = UPRIDPlugin(dict(routing_code='DEV',
                                  passport_series='1111',
                                  passport_number='111111',
                                  first_name='Test',
                                  middle_name='Test2',
                                  last_name='Test3',
                                  snils='229-785-346 20'))

        class Client(BaseSmev3Client):
            PRIVATE_KEY_FILE = 'smev3/tests/smev18_test.key'
            CERTIFICATE_FILE = 'smev3/tests/smev18_test.pem'

        client = Client(content_plugin=plugin)
        # print(client)
        client.send_request()
        # print(client.send_request())
        # print(client.factory.create('ns1:XMLDSigSignatureType'))

    def test_plugin_error(self):
        pass


class TestPlugins(TestCase):

    def test_convert_xml(self):
        content = UPRIDPlugin().make_content(routing_code='DEV',
                                             passport_series='1111',
                                             passport_number='111111',
                                             first_name='Test',
                                             middle_name='Test2',
                                             last_name='Test3',
                                             snils='229-785-346 20')
        print(content.str(indent=4))


class TestSignPlugin(TestCase):

    def test(self):
        import os
        print(os.getcwd())
        content = SignPlugin(cert_path='smev3/tests/smev18_test.pem', pkey_path='smev3/tests/smev18_test.key')\
            .build_callerinform('ns2')
        print(content.str(indent=4))