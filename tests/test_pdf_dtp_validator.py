# packages/rae-quality/tests/test_pdf_dtp_validator.py
import pytest
from engines.testing.pdf_dtp_validator import PDFDtpValidator

def test_geometry_valid_bleed():
    validator = PDFDtpValidator()
    # 90x50mm net, 94x54mm gross -> 2mm bleed on each side
    trimbox = {"width": 90.0, "height": 50.0}
    bleedbox = {"width": 94.0, "height": 54.0}
    res = validator.validate_geometry(trimbox, bleedbox, min_bleed_mm=2.0)
    assert res["has_valid_bleed"] is True
    assert res["bleed_x_mm"] == 2.0
    assert res["bleed_y_mm"] == 2.0
    assert len(res["issues"]) == 0

def test_geometry_missing_bleed():
    validator = PDFDtpValidator()
    # BleedBox equals TrimBox -> zero bleed
    trimbox = {"width": 90.0, "height": 50.0}
    bleedbox = {"width": 90.0, "height": 50.0}
    res = validator.validate_geometry(trimbox, bleedbox)
    assert res["has_valid_bleed"] is False
    assert any("Missing Bleed" in i for i in res["issues"])

def test_typography_pure_black_pass():
    validator = PDFDtpValidator()
    elements = [
        {
            "font_name": "Roboto-Bold",
            "font_size_pt": 10.0,
            "is_embedded": True,
            "color": {"c": 0, "m": 0, "y": 0, "k": 100}
        }
    ]
    res = validator.validate_typography(elements)
    assert res["fonts_embedded"] is True
    assert res["has_pure_black_text"] is True
    assert len(res["issues"]) == 0

def test_typography_composite_black_detected():
    validator = PDFDtpValidator()
    # 4-color black on small 8pt text -> registration risk
    elements = [
        {
            "font_name": "Roboto-Light",
            "font_size_pt": 8.0,
            "is_embedded": True,
            "color": {"c": 60, "m": 40, "y": 40, "k": 100}
        }
    ]
    res = validator.validate_typography(elements)
    assert res["has_pure_black_text"] is False
    assert any("Misregistration Risk" in i for i in res["issues"])

def test_spot_layer_knockout_detected():
    validator = PDFDtpValidator()
    layers = [
        {"name": "CutContour", "overprint": False}  # Overprint is False -> Critical error
    ]
    res = validator.validate_spot_layers(layers)
    assert res["overprint_valid"] is False
    assert any("Knockout Violation" in i for i in res["issues"])

def test_audit_document_full():
    validator = PDFDtpValidator()
    doc_spec = {
        "document_id": "valid-flyer-001",
        "trimbox": {"width": 148.0, "height": 210.0},
        "bleedbox": {"width": 154.0, "height": 216.0},  # 3mm bleed
        "dpi_min": 300.0,
        "text_elements": [
            {
                "font_name": "OpenSans",
                "font_size_pt": 11.0,
                "is_embedded": True,
                "color": {"c": 0, "m": 0, "y": 0, "k": 100}
            }
        ],
        "spot_layers": [
            {"name": "DieCut", "overprint": True}
        ]
    }
    audit = validator.audit_document(doc_spec)
    assert audit.is_production_ready is True
    assert audit.score == 1.0
    assert len(audit.issues) == 0
