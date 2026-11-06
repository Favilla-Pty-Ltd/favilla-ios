// Tests for CBOR.swift and Ctap.swift (no Bluetooth). CI compiles and runs:
//   swiftc Shared/CBOR.swift Shared/Ctap.swift Tests/main.swift -o ctaptests && ./ctaptests

import CryptoKit
import Foundation

var failures = 0
func check(_ ok: Bool, _ name: String, file: String = #file, line: Int = #line) {
    if ok { print("ok   \(name)") } else { failures += 1; print("FAIL \(name) (line \(line))") }
}
func hex(_ s: String) -> Data {
    var d = Data(); var i = s.startIndex
    let t = s.replacingOccurrences(of: " ", with: "")
    i = t.startIndex
    while i < t.endIndex { let j = t.index(i, offsetBy: 2); d.append(UInt8(t[i..<j], radix: 16)!); i = j }
    return d
}
func hx(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

// --- CBOR: RFC 8949 Appendix A vectors -------------------------------------------
let vectors: [(CBOR, String)] = [
    (.int(0), "00"), (.int(23), "17"), (.int(24), "1818"), (.int(100), "1864"), (.int(1000), "1903e8"),
    (.int(1_000_000), "1a000f4240"), (.int(-1), "20"), (.int(-100), "3863"), (.int(-1000), "3903e7"),
    (.text("IETF"), "6449455446"), (.bytes(hex("01020304")), "4401020304"),
    (.array([.int(1), .int(2), .int(3)]), "83010203"),
    (.map([(.text("a"), .int(1)), (.text("b"), .array([.int(2), .int(3)]))]), "a26161016162820203"),
    (.bool(false), "f4"), (.bool(true), "f5"), (.null, "f6"),
]
for (v, h) in vectors {
    check(hx(v.encoded()) == h, "encode \(h)")
    check((try? CBOR.decode(hex(h))) == v, "decode \(h)")
}
// Canonical key order: shorter encoded key first, then byte order.
check(hx(CBOR.map([(.text("type"), .int(1)), (.text("id"), .int(2))]).encoded()) == "a2626964026474797065" + "01", "canonical: id before type")
check(hx(CBOR.map([(.int(5), .int(0)), (.int(1), .int(0))]).encoded()) == "a201000500", "canonical: int keys ascending")
check((try? CBOR.decode(hex("0000"))) == nil, "decode rejects trailing bytes")
check((try? CBOR.decode(hex("5f"))) == nil, "decode rejects indefinite length")
check((try? CBOR.decode(hex("44010203"))) == nil, "decode rejects truncated bytes")

// --- Framing: the protocol doc's examples ---------------------------------------
check(Ctap.frames(cmd: Ctap.cmdMsg, payload: Ctap.getInfo, max: 20).map(hx) == ["83000104"], "frames: getInfo is 83 00 01 04")
check(Ctap.frames(cmd: Ctap.cmdPing, payload: hex("010203"), max: 20).map(hx) == ["810003010203"], "frames: ping 81 00 03 01 02 03")
let big = Data((0..<50).map { UInt8($0) })
let fs = Ctap.frames(cmd: Ctap.cmdMsg, payload: big, max: 20)
check(fs.count == 3 && fs[0].count == 20 && fs[1].count == 20 && fs[2].count == 15, "frames: 50 bytes at 20 per write is 17 + 19 + 14")
check(fs[1].first == 0x00 && fs[2].first == 0x01, "frames: continuation seq from 0")
do {   // round trip through the reassembler
    var r = Ctap.Reassembler(); var got: Ctap.Event?
    for f in fs { got = try r.feed(f) ?? got }
    check(got == Ctap.Event.message(big), "reassemble 3 frames")
} catch { check(false, "reassemble threw \(error)") }
do {
    var r = Ctap.Reassembler()
    check((try r.feed(hex("82000102"))) == Ctap.Event.keepalive(0x02), "keepalive 0x02 (waiting for the user)")
    check((try r.feed(hex("bf000106"))) == Ctap.Event.error(0x06), "framing error 0x06 (busy)")
    _ = try r.feed(hex("83000a0001020304"))
    check((try? r.feed(hex("01ffff"))) == nil, "out-of-order continuation is refused")
} catch { check(false, "events threw \(error)") }

// --- Requests ------------------------------------------------------------------
let cdh = Data(repeating: 0xAB, count: 32)
let ga = Ctap.getAssertion(rpId: "example.com", clientDataHash: cdh, allow: [], uv: true)
check(ga.first == 0x02, "getAssertion command byte")
if let m = try? CBOR.decode(ga.dropFirst()) {
    check(m[1]?.string == "example.com" && m[2]?.data == cdh && m[3] == nil, "getAssertion rpId, clientDataHash, no allowList")
    check(m[5]?["up"] == CBOR.bool(true) && m[5]?["uv"] == CBOR.bool(true), "getAssertion options up+uv")
} else { check(false, "getAssertion decodes") }
let ga2 = Ctap.getAssertion(rpId: "example.com", clientDataHash: cdh, allow: [hex("0102")], uv: false)
if let m = try? CBOR.decode(ga2.dropFirst()), case .array(let a)? = m[3] {
    check(a.count == 1 && a[0]["id"]?.data == hex("0102") && a[0]["type"]?.string == "public-key", "getAssertion allowList")
    check(m[5]?["uv"] == CBOR.bool(false), "getAssertion uv false")
} else { check(false, "getAssertion with allowList decodes") }
let mc = Ctap.makeCredential(rpId: "example.com", clientDataHash: cdh, userHandle: hex("75736572"), userName: "josh", algorithms: [-7, -8])
check(mc.first == 0x01, "makeCredential command byte")
if let m = try? CBOR.decode(mc.dropFirst()), case .array(let algs)? = m[4] {
    check(m[1]?.data == cdh && m[2]?["id"]?.string == "example.com", "makeCredential clientDataHash, rp")
    check(m[3]?["id"]?.data == hex("75736572") && m[3]?["name"]?.string == "josh", "makeCredential user")
    check(algs.count == 2 && algs[0]["alg"] == CBOR.int(-7) && algs[0]["type"]?.string == "public-key", "makeCredential pubKeyCredParams")
    check(m[7]?["rk"] == CBOR.bool(true), "makeCredential rk")
} else { check(false, "makeCredential decodes") }
check(hx(mc) == hx(Ctap.makeCredential(rpId: "example.com", clientDataHash: cdh, userHandle: hex("75736572"), userName: "josh", algorithms: [-7, -8])), "makeCredential deterministic")

// --- Responses -----------------------------------------------------------------
let credId = Data(repeating: 0xC1, count: 16)
var authReg = Data(repeating: 0x11, count: 32)                 // rpIdHash
authReg.append(0x45)                                             // flags UP|UV|AT
authReg.append(contentsOf: [0, 0, 0, 1])                         // signCount
authReg.append(Data(repeating: 0, count: 16))                    // AAGUID
authReg.append(contentsOf: [0x00, UInt8(credId.count)])
authReg.append(credId)
authReg.append(CBOR.map([(.int(1), .int(2))]).encoded())         // a stand-in COSE key
check(Ctap.credentialID(fromAuthData: authReg) == credId, "credential id from authData")
var noAT = authReg; noAT[32] = 0x05
check(Ctap.credentialID(fromAuthData: noAT) == nil, "no credential id without the AT flag")

let att = CBOR.map([(.text("alg"), .int(-7)), (.text("sig"), .bytes(hex("3045")))])
var regResp = Data([0x00])
regResp.append(CBOR.map([(.int(1), .text("packed")), (.int(2), .bytes(authReg)), (.int(3), att)]).encoded())
do {
    let r = try Ctap.parseRegistration(regResp)
    check(r.credentialID == credId && r.fmt == "packed", "registration credential id, KEY's format noted")
    let obj = try CBOR.decode(r.attestationObject)
    check(obj["fmt"]?.string == "none" && obj["authData"]?.data == authReg && obj["attStmt"] == CBOR.map([]), "attestation object is none with empty statement")
    check(hx(r.attestationObject).hasPrefix("a363666d74646e6f6e656761747453746d74a0"), "attestation object canonical: fmt none, attStmt {}")
    let p = try Ctap.parseRegistration(regResp, passAttestation: true)
    let po = try CBOR.decode(p.attestationObject)
    check(po["fmt"]?.string == "packed" && po["attStmt"] == att, "passAttestation keeps the KEY's statement")
} catch { check(false, "parseRegistration threw \(error)") }

let authA = Data(repeating: 0x22, count: 37)
var asResp = Data([0x00])
asResp.append(CBOR.map([
    (.int(1), .map([(.text("id"), .bytes(credId)), (.text("type"), .text("public-key"))])),
    (.int(2), .bytes(authA)), (.int(3), .bytes(hex("304402"))),
    (.int(4), .map([(.text("id"), .bytes(hex("75736572"))), (.text("name"), .text("josh"))])),
]).encoded())
do {
    let a = try Ctap.parseAssertion(asResp)
    check(a.credentialID == credId && a.authenticatorData == authA && a.signature == hex("304402") && a.userHandle == hex("75736572"), "assertion fields")
} catch { check(false, "parseAssertion threw \(error)") }
check((try? Ctap.parseAssertion(Data([0x27]))) == nil, "assertion refused (0x27) throws")
do { _ = try Ctap.parseAssertion(Data([0x2E])); check(false, "0x2E should throw") }
catch Ctap.Failure.status(let s) { check(s == 0x2E, "status 0x2E surfaces as .status") }
catch { check(false, "wrong error \(error)") }

// --- Checking authData -------------------------------------------------------
var good = Data(SHA256.hash(data: Data("webauthn.io".utf8)))
good.append(0x45); good.append(contentsOf: [0, 0, 0, 7]); good.append(Data(repeating: 0xAA, count: 16))
if let c = Ctap.check(authData: good, rpId: "webauthn.io") {
    check(c.rpHashMatches && c.up && c.uv && c.at && c.signCount == 7, "check: good authData")
    check(c.problems(uvRequired: true, creating: true).isEmpty, "check: no problems")
} else { check(false, "check: parses") }
if let c = Ctap.check(authData: good, rpId: "example.com") {
    check(!c.rpHashMatches && !c.problems(uvRequired: false, creating: false).isEmpty, "check: wrong site is a problem")
} else { check(false, "check: parses 2") }
var noUV = good; noUV[32] = 0x41
if let c = Ctap.check(authData: noUV, rpId: "webauthn.io") {
    check(c.problems(uvRequired: true, creating: true).count == 1 && c.problems(uvRequired: false, creating: true).isEmpty, "check: UV only matters when required")
} else { check(false, "check: parses 3") }

print(failures == 0 ? "ALL PASSED" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
