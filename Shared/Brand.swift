// Brand.swift - Favilla's look in the app, taken from favillakey.io (the login
// page in favilla-key-firmware site/login): Archivo, brass #C9A45C, ink #F4F2EE,
// the Entropy Ember mark and the FAVILLA KEY wordmark.
//
// Type scale, checked against the wordmark (15 pt in the sheet header, 17 pt on
// the app's home): labels 11 tracked, body 15, buttons 14 tracked, headline 22,
// the site name in the sheet 30 (the one thing to read against the KEY's screen).

import SwiftUI

enum Brand {
    static let bg     = Color(hex: 0x0E0D0C)
    static let card   = Color(hex: 0x1A1817)
    static let line   = Color(hex: 0x2A2725)
    static let brass  = Color(hex: 0xC9A45C)
    static let ink    = Color(hex: 0xF4F2EE)
    static let grey   = Color(hex: 0xA8A29A)   // 7.9:1 on bg
    static let faint  = Color(hex: 0x6F6A64)
    static let danger = Color(hex: 0xF2A08A)

    enum Weight { case light, regular, semibold, bold }

    /// Archivo at a size (bundled, static weights; PostScript names from the font files).
    static func font(_ size: CGFloat, _ w: Weight = .regular) -> Font {
        let name: String
        switch w {
        case .light: name = "ArchivoRoman-Light"
        case .regular: name = "ArchivoRoman-Regular"
        case .semibold: name = "ArchivoRoman-SemiBold"
        case .bold: name = "ArchivoRoman-Bold"
        }
        return .custom(name, size: size)
    }

    static let label: Font    = font(11, .semibold)
    static let body: Font     = font(15)
    static let small: Font    = font(13)
    static let headline: Font = font(22, .bold)
    static let button: Font   = font(14, .semibold)
}

extension Color {
    init(hex: UInt32) {
        self.init(red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255, blue: Double(hex & 0xFF) / 255)
    }
}

/// The Entropy Ember: a 5x5 grid, cells 14 on a 100 grid with 4 gaps (as the site's SVG).
struct EmberMark: View {
    var size: CGFloat = 22

    // Rows top to bottom; 0 dark corner, 1 outer spark, 2 diagonal, 3 inner, 4 centre.
    private static let cells: [[Int]] = [
        [0, 0, 1, 0, 0],
        [0, 2, 3, 2, 0],
        [1, 3, 4, 3, 1],
        [0, 2, 3, 2, 0],
        [0, 0, 1, 0, 0],
    ]
    private static let colours: [Color] = [Color(hex: 0x262626), Color(hex: 0x5C4A2C), Color(hex: 0x7A6238), Color(hex: 0xC9A45C), Color(hex: 0xF4F2EE)]

    var body: some View {
        Canvas { ctx, sz in
            let u = sz.width / 100
            for (r, row) in Self.cells.enumerated() {
                for (c, v) in row.enumerated() {
                    let rect = CGRect(x: (7 + CGFloat(c) * 18) * u, y: (7 + CGFloat(r) * 18) * u, width: 14 * u, height: 14 * u)
                    ctx.fill(Path(rect), with: .color(Self.colours[v]))
                }
            }
        }
        .frame(width: size, height: size)
        .accessibilityLabel("Favilla KEY")
    }
}

/// FAVILLA (bold, ink) KEY (light, brass, tracked), as on favillakey.io.
struct Wordmark: View {
    var size: CGFloat = 15

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: size * 0.32) {
            Text("FAVILLA").font(Brand.font(size, .bold)).tracking(size * 0.02).foregroundStyle(Brand.ink)
            Text("KEY").font(Brand.font(size, .light)).tracking(size * 0.18).foregroundStyle(Brand.brass)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Favilla KEY")
    }
}

/// The mark and the wordmark side by side (sheet header 22/15, app home 28/17).
struct Lockup: View {
    var mark: CGFloat = 22
    var word: CGFloat = 15

    var body: some View {
        HStack(spacing: mark * 0.45) {
            EmberMark(size: mark)
            Wordmark(size: word)
        }
    }
}

/// A full-width button in the house style.
struct BrandButton: View {
    let title: String
    var filled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(Brand.button)
                .tracking(2)
                .frame(maxWidth: .infinity, minHeight: 50)
                .background(filled ? Brand.brass : Brand.card)
                .foregroundStyle(filled ? Brand.bg : Brand.ink)
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }
}
