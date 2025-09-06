#ifndef FONT_H
#define FONT_H

#include <stdint.h>

// A pretty basic font renderer.
//
// Various fonts can be implemented by defining their
// pixel values in a header.
//
// Each character will have different widths, but all of
// them will have a normalized height.

// The main font structure. All members are read-only.
typedef struct Font {
    const uint8_t *const *asciiGlyphs;
    const uint8_t *       asciiWidths;
    uint8_t               asciiHeight;
    uint8_t               maxWidth;
    uint8_t               fontSize;
    const char *     fontName;
} Font;

#endif