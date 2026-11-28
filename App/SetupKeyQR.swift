// SetupKeyQR.swift - a QR from a two-step setup key, for the KEY to scan
// (firmware issue #18, 11 Nov 2026).
//
// Some sites show the authenticator setup key as letters ("can't scan? enter
// this key") instead of a QR. The KEY adds codes by scanning, so the phone
// draws the QR and the KEY scans the phone's screen: VAULT, Codes, ADD A CODE,
// SCAN QR. The key lives in this view's memory only: never stored, never sent
// over Bluetooth. The QR text is exactly what the KEY's reader takes
// (src/otpauth.h): otpauth://totp/<site>:<account>?secret=<KEY>&issuer=<site>
// &digits=6&period=30&algorithm=SHA1, SHA1 only.

import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct SetupKeyQR: View {
    struct Prefill: Identifiable {
        var site: String
        var account: String
        var id: String { site + "|" + account }
    }

    @State private var site: String
    @State private var account: String
    @State private var key = ""
    @State private var digits = 6
    @State private var period = 30
    @State private var image: UIImage?
    @State private var problem = ""
    @Environment(\.dismiss) private var dismiss

    init(prefill: Prefill) {
        _site = State(initialValue: prefill.site)
        _account = State(initialValue: prefill.account)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("The site showed a setup key instead of a QR? Type it here, show the QR, and scan it with the KEY: VAULT > Codes > ADD A CODE > SCAN QR. The key stays on this screen only.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    field("SITE", text: $site, hint: "github.com")
                    field("ACCOUNT", text: $account, hint: "optional: your username there")
                    field("SETUP KEY", text: $key, hint: "the letters and numbers the site shows", mono: true)
                    HStack(spacing: 20) {
                        picker("DIGITS", value: $digits, options: [6, 7, 8])
                        picker("PERIOD", value: $period, options: [30, 60])
                    }
                    if !problem.isEmpty { Text(problem).font(Brand.small).foregroundStyle(Brand.danger).fixedSize(horizontal: false, vertical: true) }
                    BrandButton(title: "SHOW QR", filled: true) { show() }
                        .disabled(key.trimmingCharacters(in: .whitespaces).isEmpty || site.trimmingCharacters(in: .whitespaces).isEmpty)
                    if let image {
                        Image(uiImage: image)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: .infinity)
                            .padding(18)
                            .background(Color.white)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                        Text("Hold the KEY's camera over the QR, about a hand's width away, with the screen bright. The KEY asks \"This account?\" and saves the code under the entry.")
                            .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    BrandButton(title: "CLEAR", filled: false) { clear() }
                }
                .padding(16)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationTitle("Setup key to QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { clear(); dismiss() }.font(Brand.button).foregroundStyle(Brand.brass) } }
        }
        .onDisappear { clear() }
    }

    private func show() {
        problem = ""
        image = nil
        switch SetupKeyQR.text(site: site, account: account, key: key, digits: digits, period: period) {
        case .success(let t):
            image = SetupKeyQR.qr(t)
            if image == nil { problem = "The QR couldn't be drawn." }
        case .failure(let f): problem = f.description
        }
    }

    private func clear() {
        key = ""; image = nil; problem = ""
    }

    // MARK: - The text

    /// The otpauth URL, or why not. The key: spaces and dashes removed, trailing
    /// `=` removed, upper case; A to Z and 2 to 7 only, 8 to 103 characters.
    static func text(site: String, account: String, key: String, digits: Int, period: Int) -> Result<String, KeySession.Failure> {
        var k = key.uppercased().filter { $0 != " " && $0 != "-" }
        while k.hasSuffix("=") { k.removeLast() }
        guard !k.isEmpty else { return .failure(KeySession.Failure("Type the setup key.")) }
        guard k.allSatisfy({ ("A"..."Z").contains($0) || ("2"..."7").contains($0) }) else {
            return .failure(KeySession.Failure("A setup key has only the letters A to Z and the digits 2 to 7. Check it against the site: 0 and 1 are never in one."))
        }
        guard (8...103).contains(k.count) else { return .failure(KeySession.Failure("A setup key is 8 to 103 characters; this one is \(k.count).")) }
        let s = site.trimmingCharacters(in: .whitespacesAndNewlines)
        let a = account.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return .failure(KeySession.Failure("Name the site.")) }
        guard (6...8).contains(digits), (1...255).contains(period) else { return .failure(KeySession.Failure("Digits 6 to 8, period 1 to 255.")) }
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        func enc(_ x: String) -> String { x.addingPercentEncoding(withAllowedCharacters: allowed) ?? x }
        let label = a.isEmpty ? enc(s) : enc(s) + ":" + enc(a)
        return .success("otpauth://totp/\(label)?secret=\(k)&issuer=\(enc(s))&digits=\(digits)&period=\(period)&algorithm=SHA1")
    }

    /// Error correction M, dark modules on white, scaled up without smoothing;
    /// the quiet zone is the white panel around it.
    static func qr(_ text: String) -> UIImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage else { return nil }
        let scale = max(1, (600 / out.extent.width).rounded(.down))
        let big = out.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cg = CIContext().createCGImage(big, from: big.extent) else { return nil }
        return UIImage(cgImage: cg)
    }

    // MARK: - Bits

    private func field(_ label: String, text: Binding<String>, hint: String, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
            TextField(hint, text: text)
                .textInputAutocapitalization(mono ? .characters : .never).autocorrectionDisabled()
                .keyboardType(mono ? .asciiCapable : .URL)
                .font(mono ? .system(size: 16, design: .monospaced) : Brand.body).foregroundStyle(Brand.ink)
                .padding(12).background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }

    private func picker(_ label: String, value: Binding<Int>, options: [Int]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
            Picker(label, selection: value) { ForEach(options, id: \.self) { Text("\($0)").tag($0) } }
                .pickerStyle(.segmented)
        }
    }
}
