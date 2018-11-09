from suds.plugin import MessagePlugin
from suds.sax.element import Element


class BasePlugin(MessagePlugin):

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
        root.insert(self.create_element('RoutingCode', prefix=prefix, text=routing_code))
        root.insert(self.create_element('passportSeries', prefix=prefix, text=passport_series))
        root.insert(self.create_element('passportNumber', prefix=prefix, text=passport_number))
        root.insert(self.create_element('lastName', prefix=prefix, text=last_name))
        root.insert(self.create_element('firstName', prefix=prefix, text=first_name))
        root.insert(self.create_element('middleName', prefix=prefix, text=middle_name))

        if snils:
            root.insert(self.create_element('snils', prefix=prefix, text=snils))
        return root


class SignPlugin(BasePlugin):

    def __init__(self, pkey_path, cert_path, pkey_password=None):
        """
        :param pkey_path: путь до файла private key
        :param cert_path: путь до файла сертификата
        :param pkey_password: ключ шифрования файла private key
        """
        self.pkey_path = pkey_path
        self.cert_path = cert_path
        self.pkey_password = pkey_password

    def marshalled(self, context):
        request_container = context.envelope.childAtPath('Body/SendRequestRequest')
        request_container.insert(self.build_callerinform(request_container.prefix))

    def build_callerinform(self, prefix):
        callerinform = self.create_element('CallerInformationSystemSignature', prefix=prefix)
        signature = self.create_element('Signature', ns=('ds', "http://www.w3.org/2000/09/xmldsig#"))
        callerinform.insert(signature)
        sign_info = self.build_sign_info(signature.prefix)
        signature.insert(sign_info)
        # todo сгенерировать SignatureValue
        signature.insert(self.create_element('SignatureValue', prefix=signature.prefix, text='SOME VALUE'))
        signature.insert(self.build_key_info(signature.prefix))
        return callerinform

    def build_sign_info(self, prefix):
        sign_info = self.create_element('SignedInfo', prefix=prefix)
        sign_info.insert(self.create_element('CanonicalizationMethod', prefix=prefix,
                                             attrs={'Algorithm': 'http://www.w3.org/2001/10/xml-exc-c14n#'}))
        sign_info.insert(self.create_element('SignatureMethod', prefix=prefix,
                                             attrs={'Algorithm': "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"}))
        sign_info.insert(self.build_reference(prefix))
        return sign_info

    def build_reference(self, prefix):
        # todo генерировать атрибут URI
        reference = self.create_element('Reference', prefix=prefix, attrs={'URI': 'SOME'})
        transforms = self.create_element('Transforms', prefix=prefix)
        transforms.insert(self.create_element('Transform', prefix=prefix,
                                              attrs={'Algorithm': 'http://www.w3.org/2001/10/xml-exc-c14n#'}))
        transforms.insert(self.create_element('Transform', prefix=prefix,
                                              attrs={'Algorithm': 'urn://smev-gov-ru/xmldsig/transform'}))
        reference.insert(transforms)
        reference.insert(self.create_element('DigestMethod', prefix=prefix,
                                             attrs={'Algorithm': 'http://www.w3.org/2001/04/xmldsig-more#gostr3411'}))
        # todo сгенерировать digest_value
        reference.insert(self.create_element('DigestValue', prefix=prefix, text='SOME VALUE'))
        return reference

    def build_key_info(self, prefix):
        key_info = self.create_element('KeyInfo', prefix=prefix)
        x509data = self.create_element('X509Data', prefix=prefix)
        # todo сгенерировать X509Certificate
        x509data.insert(self.create_element('X509Certificate', prefix=prefix, text='SOME VALUE'))
        key_info.insert(x509data)
        return key_info
