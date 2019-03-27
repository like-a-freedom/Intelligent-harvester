__author__ = 'http://stackoverflow.com/questions/26413216/pdfminer3k-has-no-method-named-create-pages-in-pdfpage'
#
# Used only when extracting indicators from PDF formatted files
#

from pdfminer3.pdfdocument import PDFDocument
from pdfminer3.pdfparser import PDFParser
from pdfminer3.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer3.converter import PDFPageAggregator
from pdfminer3.layout import LAParams, LTTextBox, LTTextLine


def convert_pdf_to_txt(path):
    fp = open(path, 'rb')
    txt = ''
    parser = PDFParser(fp)
    doc = PDFDocument()
    parser.set_document(doc)
    doc.set_parser(parser)
    doc.initialize('')
    rsrcmgr = PDFResourceManager()
    laparams = LAParams()
    device = PDFPageAggregator(rsrcmgr, laparams=laparams)
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    # Process each page contained in the document.
    for page in doc.get_pages():
        interpreter.process_page(page)
        layout = device.get_result()
        for lt_obj in layout:
            if isinstance(lt_obj, LTTextBox) or isinstance(lt_obj, LTTextLine):
                txt += lt_obj.get_text()
    return(txt)
