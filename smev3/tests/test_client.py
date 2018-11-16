import base64
from lxml import etree
from unittest import TestCase
from unittest.mock import patch

from smev3.client import BaseSmev3Client
from smev3.plugins import UPRIDPlugin, SignPlugin
from smev3.transform import Smev3Transform
from smev3.utils import get_gost_r_3410_digest, encode_c14n


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


class S(TestCase):

    def test(self):
        expected = '/jXl70XwnttJB5sSokwh8SaVHwo2gjgILSu0qBaLUAo='
        data = """
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1">
  <S:Body>
    <ns2:SendRequestRequest xmlns:ns3="urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1"
         xmlns:ns2="urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1" xmlns="urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1">
      <ns:SenderProvidedRequestData Id="SIGNED_BY_CONSUMER" xmlns="urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1" xmlns:ns="urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1" xmlns:ns2="urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1">
        <ns:MessageID>db0486d0-3c08-11e5-95e2-d4c9eff07b77</ns:MessageID>
        <ns2:MessagePrimaryContent>
          <ns1:BreachRequest xmlns:ns1="urn://x-artefacts-gibdd-gov-ru/breach/root/1.0"
                xmlns:ns2="urn://x-artefacts-gibdd-gov-ru/breach/commons/1.0"
                  xmlns:ns3="urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1" Id="PERSONAL_SIGNATURE">
            <ns1:RequestedInformation>
              <ns2:RegPointNum>Т785ЕС57</ns2:RegPointNum>
            </ns1:RequestedInformation>
            <ns1:Governance>
              <ns2:Name>ГИБДД РФ</ns2:Name>
              <ns2:Code>GIBDD</ns2:Code>
              <ns2:OfficialPerson>
                <ns3:FamilyName>Загурский</ns3:FamilyName>
                <ns3:FirstName>Андрей</ns3:FirstName>
                <ns3:Patronymic>Петрович</ns3:Patronymic>
              </ns2:OfficialPerson>
            </ns1:Governance>
          </ns1:BreachRequest>
        </ns2:MessagePrimaryContent>
        <ns:TestMessage/>
      </ns:SenderProvidedRequestData>
      <ns2:CallerInformationSystemSignature>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/>
            <ds:Reference URI="#SIGNED_BY_CONSUMER">
              <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:Transform Algorithm="urn://smev-gov-ru/xmldsig/transform"/>
              </ds:Transforms>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/>
              <ds:DigestValue>/jXl70XwnttJB5sSokwh8SaVHwo2gjgILSu0qBaLUAo=</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>J3746ks34pOcPGQpKzc0sz3n9+gjPtzZbSEEs4c3sTwbtfdaY7N/hxXzEIvXc+3ad9bc35Y8yBhZ/BYbloGt+Q==</ds:SignatureValue>
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>MIIBcDCCAR2gAwIBAgIEHVmVKDAKBgYqhQMCAgMFADAtMRAwDgYDVQQLEwdTWVNURU0xMQwwCgYDVQQKEwNJUzIxCzAJBgNVBAYTAlJVMB4XDTE1MDUwNzEyMTUzMFoXDTE4MDUwNjEyMTUzMFowLTEQMA4GA1UECxMHU1lTVEVNMTEMMAoGA1UEChMDSVMyMQswCQYDVQQGEwJSVTBjMBwGBiqFAwICEzASBgcqhQMCAiMBBgcqhQMCAh4BA0MABEDoWGZlTUWD43G1N7TEm14+QyXrJWProrzoDoCJRem169q4bezFOUODcNooQJNg3PtAizkWeFcX4b93u8fpVy7RoyEwHzAdBgNVHQ4EFgQUaRG++MAcPZvK/E2vR1BBl5G7s5EwCgYGKoUDAgIDBQADQQCg25vA3RJL3kgcJhVOHA86vnkMAtZYr6HBPa7LpEo0HJrbBF0ygKk50app1lzPdZ5TtK2itfmNgTYiuQHX3+nE</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </ds:Signature>
      </ns2:CallerInformationSystemSignature>
    </ns2:SendRequestRequest>
  </S:Body>
</S:Envelope>
"""
        xml = etree.fromstring(data)

        element = xml.getchildren()[0].getchildren()[0].getchildren()[0]
        data = etree.tostring(element)
        transformed_data = Smev3Transform(data).run()
        result = base64.b64encode(get_gost_r_3410_digest(transformed_data.encode())).decode()
        self.assertEqual(result, expected)


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