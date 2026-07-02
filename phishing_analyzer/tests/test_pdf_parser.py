import io
import os
import tempfile
import pytest
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from phishing_analyzer.server import _extract_text_from_upload

# Create a mock FileStorage object that mimics Flask's request.files FileStorage
class MockFileStorage:
    def __init__(self, filename, content_bytes):
        self.filename = filename
        self.content_bytes = content_bytes
        self._io = io.BytesIO(content_bytes)

    def read(self, *args, **kwargs):
        return self._io.read(*args, **kwargs)

def test_extract_txt_file():
    # Verify that .txt files are decoded as utf-8 directly
    raw_text = "Subject: Urgent Info\n\nPlease click here."
    file_storage = MockFileStorage("test.txt", raw_text.encode("utf-8"))
    extracted = _extract_text_from_upload(file_storage)
    assert extracted == raw_text

def test_extract_text_layer_pdf():
    # Dynamically create a PDF with a text layer using ReportLab
    temp_dir = tempfile.mkdtemp()
    pdf_path = os.path.join(temp_dir, "text_layer.pdf")
    
    try:
        c = canvas.Canvas(pdf_path, pagesize=letter)
        c.drawString(100, 750, "Hello World from Antigravity PDF Test!")
        c.drawString(100, 730, "Subject: Job posting from Capgemini Group")
        c.save()
        
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
            
        file_storage = MockFileStorage("text_layer.pdf", pdf_bytes)
        extracted = _extract_text_from_upload(file_storage)
        
        assert "Hello World" in extracted
        assert "Capgemini Group" in extracted
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        os.rmdir(temp_dir)

def test_extract_image_only_pdf_returns_sentinel():
    # Dynamically create an image-only PDF.
    # To simulate an image-only PDF, we draw a rectangle/drawing paths but no text objects.
    temp_dir = tempfile.mkdtemp()
    pdf_path = os.path.join(temp_dir, "image_only.pdf")
    
    try:
        c = canvas.Canvas(pdf_path, pagesize=letter)
        # Draw some lines and rects, but no text strings
        c.rect(100, 100, 200, 200, fill=True, stroke=True)
        c.line(50, 50, 400, 400)
        c.save()
        
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
            
        file_storage = MockFileStorage("image_only.pdf", pdf_bytes)
        extracted = _extract_text_from_upload(file_storage)
        
        # Should return the sentinel value since there is no text layer and OCR is not installed/configured
        assert extracted == "__IMAGE_ONLY_PDF__"
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        os.rmdir(temp_dir)
