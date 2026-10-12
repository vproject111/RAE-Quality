# packages/rae-quality/tests/test_golden_set.py
import pytest
from engines.testing.golden_set_runner import GoldenSetRunner
from engines.testing.pdf_dtp_validator import PDFDtpValidator

def test_golden_set_runner_all_canonical_pass():
    runner = GoldenSetRunner()
    result = runner.run_golden_set_regression()
    
    assert result["total_documents"] == 5
    assert result["passed_count"] == 5
    assert result["failed_count"] == 0
    assert result["verification_score"] == 1.0
    assert result["all_passed"] is True
    
    # Check that all 5 products are tested
    product_ids = [p["document_id"] for p in result["audits"]]
    assert "golden-01-wizytowka-standard" in product_ids
    assert "golden-02-ulotka-a5-prestige" in product_ids
    assert "golden-03-plakat-b2-reklamowy" in product_ids
    assert "golden-04-opakowanie-fefco-box" in product_ids
    assert "golden-05-kalendarz-trojdzielny" in product_ids

def test_golden_set_runner_detects_regression():
    runner = GoldenSetRunner()
    # Artificially alter one canonical product with an intentional DTP flaw
    bad_spec = {
        "document_id": "GS-REGRESSION-TEST",
        "trimbox": {"width": 90.0, "height": 50.0},
        "bleedbox": {"width": 90.0, "height": 50.0}, # Zero bleed violation
        "dpi_min": 300.0,
        "text_elements": [
            {
                "font_name": "Inter-Bold",
                "font_size_pt": 5.0, # Too small (<6pt)
                "is_embedded": False, # Missing embedding
                "color": {"c": 50, "m": 40, "y": 40, "k": 100} # Rich 4C black text
            }
        ],
        "spot_layers": []
    }
    validator = PDFDtpValidator()
    report = validator.audit_document(bad_spec)
    assert report.is_production_ready is False
    assert len(report.issues) > 0
    assert any("BleedBox" in i for i in report.issues)
    assert any("embedded" in i for i in report.issues)
    assert any("composite 4-color black" in i for i in report.issues)
