import re
from collections import OrderedDict
from lxml.etree import tostring, Element, _Comment

TEXT = re.compile(r'[\w\d]')
NAMESPACE = re.compile(r'^\{(.*)\}')
FAKE_ATTRIB = re.compile(r'fake="fake"')


class Smev3Transform:
    """Класс транформации xml элементов соггласно методочесикм рекомендациям"""

    def __init__(self, xml):
        """:param xml :type lxml.Element"""
        self.xml = xml
        self.ns_num = 1

    def add_ns(self, uri, prefix_map):
        ns = 'ns%s' % self.ns_num
        self.ns_num += 1
        prefix_map[uri] = ns
        return ns

    def transform(self, element, prefix_map=None):
        """Рекурсивная трансформация элементов.
        :param element :type lxml.Element
        :param prefix_map :type dict - мап namespaces
        :return новый сконструированный lxml.Element"""
        if prefix_map is None:
            prefix_map = dict()

        uri = element.nsmap[element.prefix]
        ns = prefix_map.get(uri)

        if ns is None:
            ns = self.add_ns(uri, prefix_map)

        ns_map = {ns: uri}

        attrib = self.sort_attrib(element.attrib, prefix_map)
        fake_attrib = dict(fake='fake') if attrib else dict()
        new_element = Element(element.tag, attrib=fake_attrib, nsmap=ns_map)

        inner = ''
        children = element.getchildren()
        if children:
            new_element.text = '{inner}'
            for child in element.getchildren():
                if not isinstance(child, _Comment):
                    inner += self.transform(child, dict(prefix_map))
        else:
            if element.text and TEXT.findall(element.text):
                new_element.text = element.text.strip()
        string_element = tostring(new_element, method='c14n', exclusive=True,  with_comments=False) \
            .decode() \
            .format(inner=inner)

        string_element = FAKE_ATTRIB.sub(str(attrib), string_element)
        return string_element

    def sort_attrib(self, attrib, prefix_map):
        l1 = []
        l2 = []

        for k, v in attrib.items():
            uri = NAMESPACE.search(k)
            if uri:
                uri = uri.group(1)
                ns = prefix_map.get(uri)
                if ns is None:
                    ns = self.add_ns(uri, prefix_map)
                attr = NAMESPACE.sub('', k)
                l1.append((attr, k, v))
            else:
                l2.append((k, v))

        l1.sort(key=lambda x: x[0])
        l1 = [(k, v) for ns, k, v in l1]
        l2.sort(key=lambda x: x[0])
        l1.extend(l2)
        result = []
        for k, v in l1:
            result.append('%s="%s"' % (k, v))

        return ' '.join(result)

    def run(self):
        return self.transform(self.xml)
