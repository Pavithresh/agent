"""
REALSAFE QR Code Generation Service
Generates cryptographic QR codes linking directly to Property Digital Passports.
"""

import io
import base64
import qrcode
import qrcode.image.svg

def generate_qr_svg(passport_url):
    """
    Generates an inline SVG string for the QR code pointing to passport_url.
    Does not require Pillow or external C dependencies.
    """
    factory = qrcode.image.svg.SvgImage
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
        image_factory=factory
    )
    qr.add_data(passport_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    stream = io.BytesIO()
    img.save(stream)
    svg_data = stream.getvalue().decode('utf-8')
    return svg_data

def generate_qr_data_uri(passport_url):
    """Returns a base64 encoded data URI suitable for <img src="..."> tags."""
    svg_data = generate_qr_svg(passport_url)
    b64 = base64.b64encode(svg_data.encode('utf-8')).decode('utf-8')
    return f"data:image/svg+xml;base64,{b64}"
