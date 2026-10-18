# packages/rae-quality/engines/testing/pdf_dtp_validator.py
from typing import Any, Dict, List, Optional
from models.risk import PDFDtpAuditResult

class PDFDtpValidator:
    """
    Production-grade DTP & PDF quality validator.
    Inspects page boxes (TrimBox/BleedBox/MediaBox), color separations,
    pure black typography, spot color overprint, and font embedding.
    """

    DEFAULT_MIN_DPI = 300.0
    DEFAULT_MIN_BLEED_MM = 2.0

    def validate_geometry(
        self,
        trimbox: Dict[str, float],
        bleedbox: Dict[str, float],
        min_bleed_mm: float = DEFAULT_MIN_BLEED_MM
    ) -> Dict[str, Any]:
        """
        Validates page box dimensions and ensures required bleeds exist.
        Dimensions in millimeters (mm).
        """
        issues = []
        warnings = []

        trim_w = trimbox.get("width", 0.0)
        trim_h = trimbox.get("height", 0.0)
        bleed_w = bleedbox.get("width", 0.0)
        bleed_h = bleedbox.get("height", 0.0)

        if trim_w <= 0 or trim_h <= 0:
            issues.append(f"Invalid TrimBox: width={trim_w}mm, height={trim_h}mm")

        if bleed_w <= 0 or bleed_h <= 0:
            issues.append(f"Invalid BleedBox: width={bleed_w}mm, height={bleed_h}mm")

        # Bleed delta calculation
        bleed_x = (bleed_w - trim_w) / 2.0
        bleed_y = (bleed_h - trim_h) / 2.0

        if bleed_w <= trim_w or bleed_h <= trim_h:
            issues.append(
                f"Missing Bleed: BleedBox ({bleed_w}x{bleed_h}mm) is not larger than TrimBox ({trim_w}x{trim_h}mm)!"
            )
            has_valid_bleed = False
        elif bleed_x < min_bleed_mm or bleed_y < min_bleed_mm:
            warnings.append(
                f"Insufficient Bleed: Expected at least {min_bleed_mm}mm, but found "
                f"horizontal={bleed_x:.1f}mm, vertical={bleed_y:.1f}mm."
            )
            has_valid_bleed = False
        else:
            has_valid_bleed = True

        return {
            "has_valid_bleed": has_valid_bleed,
            "bleed_x_mm": round(bleed_x, 2),
            "bleed_y_mm": round(bleed_y, 2),
            "issues": issues,
            "warnings": warnings
        }

    def validate_typography(self, text_elements: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verifies font embedding and pure K channel enforcement for body text (<= 12pt).
        """
        issues = []
        warnings = []
        fonts_embedded = True
        has_pure_black = True

        for idx, el in enumerate(text_elements):
            font_name = el.get("font_name", "Unknown")
            is_embedded = el.get("is_embedded", True)
            font_size_pt = el.get("font_size_pt", 10.0)
            color = el.get("color", {})  # expected dict: {"c": 0, "m": 0, "y": 0, "k": 100} or RGB

            if not is_embedded:
                fonts_embedded = False
                issues.append(f"Font '{font_name}' in element #{idx} is not embedded in the document!")

            # Check black text
            if font_size_pt <= 12.0:
                is_black = False
                if "k" in color:
                    # CMYK check
                    c, m, y, k = color.get("c", 0), color.get("m", 0), color.get("y", 0), color.get("k", 0)
                    if k >= 90:
                        is_black = True
                        if c > 5 or m > 5 or y > 5:
                            has_pure_black = False
                            issues.append(
                                f"Misregistration Risk: Small text ({font_size_pt}pt, '{font_name}') uses "
                                f"composite 4-color black (C:{c} M:{m} Y:{y} K:{k}). Must be pure 100% K!"
                            )
                elif "r" in color:
                    # RGB check (RGB black 0,0,0 must be converted to 100% K during preflight)
                    r, g, b = color.get("r", 0), color.get("g", 0), color.get("b", 0)
                    if r < 15 and g < 15 and b < 15:
                        warnings.append(
                            f"RGB Black detected on small text ({font_size_pt}pt): "
                            f"Requires automatic CMYK pure K conversion."
                        )

        return {
            "fonts_embedded": fonts_embedded,
            "has_pure_black_text": has_pure_black,
            "issues": issues,
            "warnings": warnings
        }

    def validate_spot_layers(self, spot_layers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validates technical layers (CutContour, Varnish, White ink)
        and verifies that Overprint is strictly enabled.
        """
        issues = []
        warnings = []
        spot_names = []
        overprint_valid = True

        for layer in spot_layers:
            name = layer.get("name", "")
            spot_names.append(name)
            is_overprint = layer.get("overprint", False)

            # Known technical layers requiring overprint
            is_technical = any(tech in name.lower() for tech in ["cut", "varnish", "lakier", "white", "biel", "die"])

            if is_technical and not is_overprint:
                overprint_valid = False
                issues.append(
                    f"Knockout Violation: Technical spot color '{name}' has overprint=False! "
                    f"This will cause the RIP to knock out the artwork underneath."
                )

        return {
            "spot_colors": spot_names,
            "overprint_valid": overprint_valid,
            "issues": issues,
            "warnings": warnings
        }

    def audit_document(self, doc_spec: Dict[str, Any]) -> PDFDtpAuditResult:
        """
        Performs a full DTP quality audit on a document specification.
        """
        trimbox = doc_spec.get("trimbox", {"width": 90.0, "height": 50.0})
        bleedbox = doc_spec.get("bleedbox", {"width": 94.0, "height": 54.0})
        min_bleed = doc_spec.get("min_bleed_mm", self.DEFAULT_MIN_BLEED_MM)
        dpi = doc_spec.get("dpi_min", 300.0)
        text_elements = doc_spec.get("text_elements", [])
        spot_layers = doc_spec.get("spot_layers", [])

        geom_res = self.validate_geometry(trimbox, bleedbox, min_bleed_mm=min_bleed)
        typo_res = self.validate_typography(text_elements)
        spot_res = self.validate_spot_layers(spot_layers)

        all_issues = geom_res["issues"] + typo_res["issues"] + spot_res["issues"]
        all_warnings = geom_res["warnings"] + typo_res["warnings"] + spot_res["warnings"]

        if dpi < 250.0:
            all_issues.append(f"Low Resolution: Document DPI is {dpi}, below minimum 250 DPI threshold!")

        is_production_ready = len(all_issues) == 0
        score = max(0.0, 1.0 - (len(all_issues) * 0.3) - (len(all_warnings) * 0.05))

        return PDFDtpAuditResult(
            document_id=doc_spec.get("document_id", "doc-preview"),
            is_production_ready=is_production_ready,
            score=round(score, 2),
            trimbox_mm=trimbox,
            bleedbox_mm=bleedbox,
            has_valid_bleed=geom_res["has_valid_bleed"],
            dpi_min=dpi,
            has_pure_black_text=typo_res["has_pure_black_text"],
            spot_colors=spot_res["spot_colors"],
            overprint_valid=spot_res["overprint_valid"],
            fonts_embedded=typo_res["fonts_embedded"],
            issues=all_issues,
            warnings=all_warnings
        )
