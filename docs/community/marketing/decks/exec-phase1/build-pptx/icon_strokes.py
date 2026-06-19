"""Shared icon stroke-width presets for the native slide modules.

Tabler outline icons ship with stroke-width=2 on a 24-px viewBox. When
rasterised to PNG and displayed at typical icon sizes (60–96 px), Tabler's
default outline reads as visually heavy. The build patches the SVG's
stroke-width attribute before rasterising so we can pick the weight
deliberately per slide.

Usage in a slide module:

    from icon_strokes import STROKE_THIN, STROKE_REGULAR, STROKE_BOLD

    def add_some_diagram_native(slide, *, ..., icon_stroke=STROKE_THIN):
        ...
        png = rasterize_recolored(icon_path, 192, "0F6BFF",
                                  stroke_width=icon_stroke)

Visual reference (rendered at 60-px display, after PowerPoint scale-down):

    STROKE_THIN     1.0    ~1.25 px outline. Matches the deck's SVG variants
                            (which use stroke-width=2.4 with non-scaling-
                            stroke). Looks crisp at small sizes.
    STROKE_REGULAR  1.5    ~1.9  px outline. Middle ground; visible but not
                            heavy. Good for medium sized icons (~80 px).
    STROKE_BOLD     2.0    ~2.5  px outline. Tabler's own default; reads as
                            intentional weight when the icon is the
                            slide's hero element.
"""

STROKE_THIN     = 1.0
STROKE_REGULAR  = 1.5
STROKE_BOLD     = 2.0
