from unittest import TestCase

from smev3.client import BaseSmev3Client
from smev3.plugins import UPRIDPlugin, SignPlugin


class TestBaseSmev3Client(TestCase):

    def test(self):
        plugin = UPRIDPlugin(dict(routing_code='DEV',
                                  passport_series='1111',
                                  passport_number='111111',
                                  first_name='Test',
                                  middle_name='Test2',
                                  last_name='Test3',
                                  snils='229-785-346 20'))
        client = BaseSmev3Client(content_plugin=plugin)
        print(client)
        print(client.send_request())
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
        content = SignPlugin().build_callerinform('ns2')
        print(content.str(indent=4))