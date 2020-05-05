from endesive.pdf.PyPDF2 import generic as pdf


def makeObject(obj):
    if isinstance(obj, pdf.PdfObject):
        return obj
    if isinstance(obj, int):
        return pdf.NumberObject(obj)
    if isinstance(obj, float):
        return pdf.NumberObject(obj)
    if isinstance(obj, str):
        return pdf.createStringObject(obj)
    if isinstance(obj, (list, tuple)):
        result = pdf.ArrayObject()
        for v in obj:
            v = makeObject(v)
            result.append(v)
        return result
    if isinstance(obj, dict):
        result = PdfDict()
        for k, v in obj.items():
            v = makeObject(v)
            result[k] = v
        return result
    raise ValueError("can`t convert to PdfObject", obj)


class PdfDict(pdf.DictionaryObject):
    indirect = False
    stream = None

    def __init__(self, *args, **kwargs):
        super(PdfDict, self).__init__({})
        for k, v in kwargs.items():
            self[k] = v

    def __setitem__(self, k, v):
        if k == "stream":
            if isinstance(v, str):
                v = v.encode("latin1")
            self.stream = v
            return
        if not isinstance(k, pdf.NameObject):
            k = PdfName(k)
        v = makeObject(v)
        super(PdfDict, self).__setitem__(k, v)


class IndirectPdfDict(PdfDict):
    indirect = True


def PdfName(name):
    return pdf.NameObject("/" + name)


def PdfString(s):
    return pdf.createStringObject(s)


def PdfArray(l):
    result = pdf.ArrayObject([])
    for v in l:
        v = makeObject(v)
        result.append(v)
    return result
