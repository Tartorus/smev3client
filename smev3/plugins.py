import base64
import re
import uuid

from lxml import etree
from suds.plugin import MessagePlugin
from suds.sax.element import Element

from smev3.exceptions import PluginError
from smev3.utils import load_certificate, encode_c14n, get_gost_r_3410_digest, get_gost_r_34102001_signature


class BasePlugin(MessagePlugin):

    NS_MAP = {'ds': 'http://www.w3.org/2000/09/xmldsig#',
              'ns0': 'urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.2',
              'ns1': 'urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.2',
              'ns2': 'urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.2',
              'S': 'http://schemas.xmlsoap.org/soap/envelope/'}

    def create_element(self, name, ns=None, prefix=None, attrs=None, text=None):
        """Создание нового элемента"""
        new_element = Element(name, ns=ns)
        if prefix:
            new_element.setPrefix(prefix)

        if attrs:
            for k, v in attrs.items():
                new_element.set(k, v)

        if text:
            new_element.setText(text)
        return new_element


class ContentPlugin(BasePlugin):

    def __init__(self, content_kwargs=None):
        if content_kwargs is None:
            content_kwargs = dict()
        self.content_kwargs = content_kwargs

    def marshalled(self, context):
        content_container = self.get_content_container(context)
        content = self.make_content(**self.content_kwargs)
        content_container.insert(content)

    def get_content_container(self, context):
        return context.envelope.childAtPath('Body/SendRequestRequest/SenderProvidedRequestData/MessagePrimaryContent')

    def make_content(self, *args, **kwargs):
        raise NotImplementedError()


class UPRIDPlugin(ContentPlugin):

    def make_content(self, routing_code, passport_series, passport_number,
                     first_name, middle_name, last_name, snils=None):
        ns = ('tns', "urn://mincomsvyaz/esia/uprid/1.2.0")
        root = self.create_element('ESIADataVerifyRequest', ns=ns)
        root.addPrefix('ns2', "urn://mincomsvyaz/esia/commons/rg_sevices_types/1.2.0")
        prefix = root.prefix
        root.append(self.create_element('RoutingCode', prefix=prefix, text=routing_code))
        root.append(self.create_element('passportSeries', prefix=prefix, text=passport_series))
        root.append(self.create_element('passportNumber', prefix=prefix, text=passport_number))
        root.append(self.create_element('lastName', prefix=prefix, text=last_name))
        root.append(self.create_element('firstName', prefix=prefix, text=first_name))
        root.append(self.create_element('middleName', prefix=prefix, text=middle_name))

        if snils:
            root.append(self.create_element('snils', prefix=prefix, text=snils))
        return root


class SignPlugin(BasePlugin):

    C_14 = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    SIGNATURE_METHOD = 'http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411'
    TRANSFORM = 'urn://smev-gov-ru/xmldsig/run'
    DIGEST_METHOD = 'http://www.w3.org/2001/04/xmldsig-more#gostr3411'

    DIGEST_VALUE = '{DIGESTVALUE}'
    SIGNATURE_VALUE = '{SIGNATUREVALUE}'

    def __init__(self, pkey_path, cert_path, pkey_password=None):
        """
        :param pkey_path: путь до файла private key
        :param cert_path: путь до файла сертификата
        :param pkey_password: ключ шифрования файла private key
        """
        self.pkey_path = pkey_path
        self.cert_path = cert_path
        self.pkey_password = pkey_password
        self.URI_ID = 'UNIQ_' + str(uuid.uuid4())

    def marshalled(self, context):
        request_container = context.envelope.childAtPath('Body/SendRequestRequest')
        provided_data = request_container.childAtPath('SenderProvidedRequestData')
        provided_data.set('Id', self.URI_ID)
        request_container.append(self.build_callerinform(request_container.prefix))

    def sending(self, context):
        with open('in.xml', 'wb') as o:
            o.write(context.envelope)
        xml = encode_c14n(etree.fromstring(context.envelope))
        with open('canon.xml', 'wb') as o:
            o.write(xml)
        xml = self.set_digest_value(xml)
        xml = self.set_signature_value(xml)
        context.envelope = xml
        with open('signed.xml', 'wb') as o:
            o.write(context.envelope)

    def build_callerinform(self, prefix):
        callerinform = self.create_element('CallerInformationSystemSignature', prefix=prefix)
        signature = self.create_element('Signature', ns=('ds', self.NS_MAP['ds']))
        callerinform.append(signature)
        sign_info = self.build_sign_info(signature.prefix)
        signature.append(sign_info)
        signature.append(self.create_element('SignatureValue', prefix=signature.prefix, text=self.SIGNATURE_VALUE))
        signature.append(self.build_key_info(signature.prefix))
        return callerinform

    def build_sign_info(self, prefix):
        sign_info = self.create_element('SignedInfo', prefix=prefix)
        sign_info.append(self.create_element('CanonicalizationMethod', prefix=prefix,
                                             attrs={'Algorithm': self.C_14}))
        sign_info.append(self.create_element('SignatureMethod', prefix=prefix,
                                             attrs={'Algorithm': self.SIGNATURE_METHOD}))
        sign_info.append(self.build_reference(prefix))
        return sign_info

    def build_reference(self, prefix):
        reference = self.create_element('Reference', prefix=prefix, attrs={'URI': '#' + self.URI_ID})
        transforms = self.create_element('Transforms', prefix=prefix)
        transforms.append(self.create_element('Transform', prefix=prefix,
                                              attrs={'Algorithm': self.C_14}))
        transforms.append(self.create_element('Transform', prefix=prefix,
                                              attrs={'Algorithm': self.TRANSFORM}))
        reference.append(transforms)
        reference.append(self.create_element('DigestMethod', prefix=prefix,
                                             attrs={'Algorithm': self.DIGEST_METHOD}))

        reference.append(self.create_element('DigestValue', prefix=prefix, text=self.DIGEST_VALUE))
        return reference

    def build_key_info(self, prefix):
        key_info = self.create_element('KeyInfo', prefix=prefix)
        x509data = self.create_element('X509Data', prefix=prefix)
        text = load_certificate(self.cert_path)
        x509data.append(self.create_element('X509Certificate', prefix=prefix, text=text))
        key_info.append(x509data)
        return key_info

    def set_digest_value(self, xml):
        pattern = re.compile(rb'<[a-z0-9]+:SenderProvidedRequestData[^>]+>.*</[a-z0-9]+:SenderProvidedRequestData>')
        try:
            content = re.findall(pattern, xml)[0]
            with open('digest_content.xml', 'wb') as o:
                o.write(content)
        except IndexError:
            raise PluginError('Не найден контент для хэширования')
        else:
            digest_hash = base64.b64encode(get_gost_r_3410_digest(content))
        return xml.replace(self.DIGEST_VALUE.encode(), digest_hash)

    def set_signature_value(self, xml):
        pattern = re.compile(rb'<[a-z0-9]+:SignedInfo>.*</[a-z0-9]+:SignedInfo>')
        try:
            sign_info = re.findall(pattern, xml)[0]
            with open('signed_content.xml', 'wb') as o:
                o.write(sign_info)
        except IndexError:
            raise PluginError('Не найден элемент SignedInfo')
        else:
            sign_hash = get_gost_r_3410_digest(sign_info)
        binary_signature = get_gost_r_34102001_signature(sign_hash,
                                                         pkey_filename=self.pkey_path,
                                                         passwd=self.pkey_password)
        return xml.replace(self.SIGNATURE_VALUE.encode(), base64.b64encode(binary_signature))


    # def sending(self, context):
        # xml_doc = etree.fromstring(context.envelope)
        # self.set_digest_value(xml_doc)
        # self.set_signature_value(xml_doc)
        # print(encode_c14n(xml_doc))
        # context.envelope = encode_c14n(xml_doc)

    # def set_signature_value(self, xml_doc):
    #     signed_info = xml_doc.find('.//ds:SignedInfo', self.NS_MAP)
    #     signed_info_c14_data = encode_c14n(signed_info)
    #     print(self.digest_hash)
    #     binary_signature = get_gost_r_34102001_signature(self.digest_hash,
    #                                                      pkey_filename=self.pkey_path,
    #                                                      passwd=self.pkey_password)
    #     signature_value = xml_doc.find('.//ds:SignatureValue', self.NS_MAP)
    #     signature_value.text = base64.b64encode(binary_signature)

    # def set_digest_value(self, xml_doc):
    #     digest_value = xml_doc.find('.//ds:DigestValue', self.NS_MAP)
    #     data = xml_doc.find('.//ns0:SenderProvidedRequestData', self.NS_MAP)
    #     body_c14_data = encode_c14n(data)
    #     print(body_c14_data)
    #     self.digest_hash = base64.b64encode(get_gost_r_3410_digest(body_c14_data))
    #     digest_value.text = self.digest_hash
