# packages/rae-quality/engines/testing/golden_set_runner.py
from typing import Any, Dict, List, Optional
from engines.testing.pdf_dtp_validator import PDFDtpValidator
from models.risk import PDFDtpAuditResult

class GoldenSetRunner:
    """
    Executes automated DTP & PDF regression audits across a canonical Golden Set
    of reference print products (Business cards, A5 Flyers, B2 Posters, FEFCO Packaging, Trifold Calendars).
    """

    def __init__(self, validator: Optional[PDFDtpValidator] = None):
        self.validator = validator or PDFDtpValidator()
        self._golden_set = self._build_canonical_golden_set()

    def _build_canonical_golden_set(self) -> List[Dict[str, Any]]:
        return [
            {
                "document_id": "golden-01-wizytowka-standard",
                "name": "Wizytówka 90x50mm Standard z lakierem UV",
                "product_type": "business_card",
                "trimbox": {"width": 90.0, "height": 50.0},
                "bleedbox": {"width": 94.0, "height": 54.0},
                "min_bleed_mm": 2.0,
                "dpi_min": 300.0,
                "text_elements": [
                    {
                        "font_name": "Inter-Medium",
                        "font_size_pt": 9.0,
                        "is_embedded": True,
                        "color": {"c": 0, "m": 0, "y": 0, "k": 100}  # Pure K
                    },
                    {
                        "font_name": "Inter-Bold",
                        "font_size_pt": 14.0,
                        "is_embedded": True,
                        "color": {"c": 20, "m": 100, "y": 90, "k": 10}
                    }
                ],
                "spot_layers": [
                    {"name": "CutContour", "overprint": True},
                    {"name": "Varnish_UV", "overprint": True}
                ]
            },
            {
                "document_id": "golden-02-ulotka-a5-prestige",
                "name": "Ulotka A5 Prestige ze spadami 3mm",
                "product_type": "flyer",
                "trimbox": {"width": 148.0, "height": 210.0},
                "bleedbox": {"width": 154.0, "height": 216.0},
                "min_bleed_mm": 3.0,
                "dpi_min": 300.0,
                "text_elements": [
                    {
                        "font_name": "Roboto-Regular",
                        "font_size_pt": 10.0,
                        "is_embedded": True,
                        "color": {"c": 0, "m": 0, "y": 0, "k": 100}
                    }
                ],
                "spot_layers": []
            },
            {
                "document_id": "golden-03-plakat-b2-reklamowy",
                "name": "Plakat B2 Reklamowy 500x700mm",
                "product_type": "poster",
                "trimbox": {"width": 500.0, "height": 700.0},
                "bleedbox": {"width": 506.0, "height": 706.0},
                "min_bleed_mm": 3.0,
                "dpi_min": 300.0,
                "text_elements": [
                    {
                        "font_name": "Montserrat-Black",
                        "font_size_pt": 36.0,
                        "is_embedded": True,
                        "color": {"c": 0, "m": 80, "y": 95, "k": 0}
                    }
                ],
                "spot_layers": []
            },
            {
                "document_id": "golden-04-opakowanie-fefco-box",
                "name": "Pudełko wykrawane FEFCO z liniami bigu i cięcia",
                "product_type": "packaging_box",
                "trimbox": {"width": 200.0, "height": 150.0},
                "bleedbox": {"width": 206.0, "height": 156.0},
                "min_bleed_mm": 3.0,
                "dpi_min": 300.0,
                "text_elements": [
                    {
                        "font_name": "Helvetica-Light",
                        "font_size_pt": 8.0,
                        "is_embedded": True,
                        "color": {"c": 0, "m": 0, "y": 0, "k": 100}
                    }
                ],
                "spot_layers": [
                    {"name": "DieCut_Line", "overprint": True},
                    {"name": "Crease_Line", "overprint": True},
                    {"name": "White_Underprint", "overprint": True}
                ]
            },
            {
                "document_id": "golden-05-kalendarz-trojdzielny",
                "name": "Kalendarz trójdzielny z główką wypukłą",
                "product_type": "calendar",
                "trimbox": {"width": 310.0, "height": 810.0},
                "bleedbox": {"width": 316.0, "height": 816.0},
                "min_bleed_mm": 3.0,
                "dpi_min": 300.0,
                "text_elements": [
                    {
                        "font_name": "Calibri-Bold",
                        "font_size_pt": 12.0,
                        "is_embedded": True,
                        "color": {"c": 0, "m": 0, "y": 0, "k": 100}
                    }
                ],
                "spot_layers": [
                    {"name": "Head_CutContour", "overprint": True}
                ]
            }
        ]

    def run_golden_set_regression(self) -> Dict[str, Any]:
        """
        Audits all documents in the Golden Set and calculates the collective DTP regression score.
        """
        results: List[PDFDtpAuditResult] = []
        all_passed = True
        failed_docs = []

        for doc in self._golden_set:
            audit = self.validator.audit_document(doc)
            results.append(audit)
            if not audit.is_production_ready:
                all_passed = False
                failed_docs.append({"document_id": audit.document_id, "issues": audit.issues})

        passed_count = sum(1 for r in results if r.is_production_ready)
        total_count = len(results)
        score = (passed_count / total_count) if total_count > 0 else 0.0

        return {
            "all_passed": all_passed,
            "verification_score": round(score, 2),
            "total_documents": total_count,
            "passed_count": passed_count,
            "failed_count": total_count - passed_count,
            "failed_documents": failed_docs,
            "audits": [r.dict() for r in results]
        }
