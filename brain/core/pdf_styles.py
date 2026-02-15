from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def _register_font(alias: str, candidates: list[Path]) -> bool:
    for path in candidates:
        if not path.exists():
            continue
        try:
            pdfmetrics.registerFont(TTFont(alias, str(path)))
            return True
        except Exception:
            continue
    return False


def _font_candidates(filename: str) -> list[Path]:
    return [
        Path(filename),
        Path("fonts") / filename,
        Path("assets") / "fonts" / filename,
        Path("docs") / "assets" / "fonts" / filename,
        Path("/Library/Fonts") / filename,
        Path.home() / "Library" / "Fonts" / filename,
    ]


def _resolve_fonts(branding: dict) -> dict[str, str]:
    fonts = {
        "display_regular": "Times-Roman",
        "display_bold": "Times-Bold",
        "body_regular": "Helvetica",
        "body_bold": "Helvetica-Bold",
        "mono": "Courier",
    }

    if _register_font(
        "CASMDisplay-Regular",
        [
            Path(str(branding.get("display_font_regular_path", ""))),
            *_font_candidates("LibreBaskerville-Regular.ttf"),
        ],
    ):
        fonts["display_regular"] = "CASMDisplay-Regular"
    if _register_font(
        "CASMDisplay-Bold",
        [
            Path(str(branding.get("display_font_bold_path", ""))),
            *_font_candidates("LibreBaskerville-Bold.ttf"),
        ],
    ):
        fonts["display_bold"] = "CASMDisplay-Bold"
    if _register_font(
        "CASMBody-Regular",
        [
            Path(str(branding.get("body_font_regular_path", ""))),
            *_font_candidates("Manrope-Regular.ttf"),
        ],
    ):
        fonts["body_regular"] = "CASMBody-Regular"
    if _register_font(
        "CASMBody-Bold",
        [
            Path(str(branding.get("body_font_bold_path", ""))),
            *_font_candidates("Manrope-Bold.ttf"),
        ],
    ):
        fonts["body_bold"] = "CASMBody-Bold"
    if _register_font(
        "CASMMono-Regular",
        [
            Path(str(branding.get("mono_font_path", ""))),
            *_font_candidates("IBMPlexMono-Regular.ttf"),
        ],
    ):
        fonts["mono"] = "CASMMono-Regular"
    return fonts


def _hex_color(value: str, fallback: str) -> colors.Color:
    if not value or not _HEX_COLOR.match(value):
        return colors.HexColor(fallback)
    return colors.HexColor(value)


def get_casm_styles(branding_config: Optional[dict] = None) -> dict:
    """Return a style map for PDF rendering.

    Args:
        branding_config (dict | None): Optional branding overrides.

    Returns:
        dict: Named ReportLab ParagraphStyle objects.
    """
    branding = branding_config or {}
    fonts = _resolve_fonts(branding)

    primary = _hex_color(branding.get("primary_color", ""), "#0A1628")
    secondary = _hex_color(branding.get("secondary_color", ""), "#2E5BFF")
    critical = _hex_color(branding.get("critical_color", ""), "#F04438")
    high = _hex_color(branding.get("high_color", ""), "#F79009")
    medium = _hex_color(branding.get("medium_color", ""), "#F79009")
    low = _hex_color(branding.get("low_color", ""), "#5A82FF")
    info = _hex_color(branding.get("info_color", ""), "#475467")
    neutral_bg = _hex_color(branding.get("neutral_bg_color", ""), "#F5F6F8")
    neutral_border = _hex_color(branding.get("neutral_border_color", ""), "#EAECF0")

    stylesheet = getSampleStyleSheet()

    styles: dict[str, object] = {
        "CoverTitle": ParagraphStyle(
            "CoverTitle",
            parent=stylesheet["Title"],
            fontName=fonts["display_bold"],
            fontSize=24,
            leading=28,
            textColor=primary,
            alignment=TA_CENTER,
        ),
        "Heading1": ParagraphStyle(
            "Heading1",
            parent=stylesheet["Heading1"],
            fontName=fonts["display_bold"],
            fontSize=18,
            leading=22,
            textColor=primary,
            spaceAfter=10,
        ),
        "Heading2": ParagraphStyle(
            "Heading2",
            parent=stylesheet["Heading2"],
            fontName=fonts["display_regular"],
            fontSize=14,
            leading=18,
            textColor=primary,
            spaceAfter=6,
        ),
        "BodyText": ParagraphStyle(
            "BodyText",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_regular"],
            fontSize=11,
            leading=13,
            spaceAfter=6,
        ),
        "Code": ParagraphStyle(
            "Code",
            parent=stylesheet["BodyText"],
            fontName=fonts["mono"],
            fontSize=9,
            leading=11,
            spaceAfter=6,
            backColor=neutral_bg,
        ),
        "Critical": ParagraphStyle(
            "Critical",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_bold"],
            textColor=critical,
        ),
        "High": ParagraphStyle(
            "High",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_bold"],
            textColor=high,
        ),
        "Medium": ParagraphStyle(
            "Medium",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_bold"],
            textColor=medium,
        ),
        "Low": ParagraphStyle(
            "Low",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_bold"],
            textColor=low,
        ),
        "Info": ParagraphStyle(
            "Info",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_bold"],
            textColor=info,
        ),
        "TableHeader": ParagraphStyle(
            "TableHeader",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_bold"],
            fontSize=11,
            leading=12,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "TableBody": ParagraphStyle(
            "TableBody",
            parent=stylesheet["BodyText"],
            fontName=fonts["body_regular"],
            fontSize=9,
            leading=11,
        ),
        "Secondary": ParagraphStyle(
            "Secondary",
            parent=stylesheet["BodyText"],
            textColor=secondary,
        ),
    }

    styles["_palette"] = {
        "primary": primary,
        "secondary": secondary,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "neutral_bg": neutral_bg,
        "neutral_border": neutral_border,
    }
    styles["_footer_text"] = branding.get("footer_text") or "Confidential"
    styles["_fonts"] = fonts

    return styles
