// Tests for CBOR.swift, Ctap.swift and KeyApi.swift (no Bluetooth). CI compiles and runs:
//   swiftc Shared/CBOR.swift Shared/Ctap.swift Shared/KeyLink.swift App/KeyApi.swift App/NostrLink.swift App/LinkLog.swift Tests/main.swift -o ctaptests && ./ctaptests

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

// --- Passwords (9c) -----------------------------------------------------------
do {
    var r = Ctap.Reassembler()
    var ans = Data([0x00, 4]); ans.append(Data("josh".utf8)); ans.append(6); ans.append(Data("s3cr3t".utf8))
    var got: Ctap.Event?
    for f in Ctap.frames(cmd: Ctap.cmdAnswer, payload: ans, max: 8) { got = try r.feed(f) ?? got }
    check(got == Ctap.Event.answer(ans), "answer 0x84 reassembles across frames")
    let l = try Ctap.parseFill(ans)
    check(l.user == "josh" && l.password == "s3cr3t", "parseFill login")
    var noUser = Data([0x00, 0]); noUser.append(3); noUser.append(Data("abc".utf8))
    let l2 = try Ctap.parseFill(noUser)
    check(l2.user == "" && l2.password == "abc", "parseFill empty username")
} catch { check(false, "fill threw \(error)") }
for st: UInt8 in [0x02, 0x03, 0x05] {
    do { _ = try Ctap.parseFill(Data([st])); check(false, "status should throw") }
    catch Ctap.FillFailure.status(let s) { check(s == st, String(format: "fill status 0x%02X", st)) }
    catch { check(false, "wrong error") }
}
check((try? Ctap.parseFill(Data([0x00, 5, 0x61]))) == nil, "parseFill rejects a short body")
check((try? Ctap.parseFill(Data([0x00, 0, 1, 0x61, 0x62]))) == nil, "parseFill rejects trailing bytes")

// --- FILL request bytes (9d) -----------------------------------------------------
check(KeyLink.fillBody(site: "https://GitHub.com/login").map(hx) == "340a6769746875622e636f6d00", "FILL: host from a URL, lower-case, no username")
check(KeyLink.fillBody(site: "github.com", user: "josh").map(hx) == "340a6769746875622e636f6d046a6f7368", "FILL: with username")
check(KeyLink.fillBody(site: "github.com", user: String(repeating: "x", count: 101)).map(hx) == "340a6769746875622e636f6d00", "FILL: over-long username left out")
check(KeyLink.fillBody(site: "My Bank", appName: true).map(hx) == "34074d792042616e6b00", "FILL: app name kept as written")
check(KeyLink.fillBody(site: "bad site") == nil, "FILL: a domain with a space is refused")

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


// --- Nostr over Bluetooth: the API request bytes (KeyApi.swift, ApiWire) ----------
do {
    let r = ApiRequest(method: "POST", host: "localhost", path: "/api/sign",
                       headers: ["x-favilla-session": "ab", "Content-Type": "application/json", "X-Favilla-Ctr": "7"],
                       body: Data("{}".utf8), timeout: 10)
    // 02 | 0900 "/api/sign" | 02 hdrs: 01 0200 "ab", 03 0100 "7" | 0200 "{}"
    check(ApiWire.encode(r).map(hx) == "02" + "0900" + hx(Data("/api/sign".utf8)) + "02" + "010200" + hx(Data("ab".utf8)) + "030100" + hx(Data("7".utf8)) + "0200" + hx(Data("{}".utf8)),
          "API: POST /api/sign with two KEY headers, Content-Type dropped")
    var g = r; g.method = "get"; g.headers = [:]; g.body = Data()
    check(ApiWire.encode(g).map(hx) == "01" + "0900" + hx(Data("/api/sign".utf8)) + "00" + "0000", "API: GET, no headers, empty body")
    var bad = r; bad.path = "/index.html"
    check(ApiWire.encode(bad) == nil, "API: only /api/ paths")
    bad = r; bad.method = "PUT"
    check(ApiWire.encode(bad) == nil, "API: only GET and POST")
    bad = r; bad.body = Data(count: ApiWire.bodyMax + 1)
    check(ApiWire.encode(bad) == nil, "API: body over 32 KB refused")
    let ans = hex("c800" + "01" + "0200") + Data("{}".utf8)
    check(ApiWire.decodeAnswer(ans) == ApiResponse(status: 200, contentType: "application/json", body: Data("{}".utf8)), "API answer: 200 JSON")
    check(ApiWire.decodeAnswer(hex("9101" + "00" + "0000")) == ApiResponse(status: 401, contentType: "", body: Data()), "API answer: 401 empty")
    check(ApiWire.decodeAnswer(hex("c800" + "01" + "0300") + Data("{}".utf8)) == nil, "API answer: length mismatch refused")
    check(ApiWire.decodeAnswer(hex("0000" + "01" + "0000")) == nil, "API answer: status 0 refused")
}
check(WifiTransport.isLocal("192.168.20.24") && WifiTransport.isLocal("favilla-8fc17c68.local") && WifiTransport.isLocal("10.0.0.5:80"), "Wi-Fi: local addresses")
check(WifiTransport.isLocal("172.20.1.1") && !WifiTransport.isLocal("172.32.1.1"), "Wi-Fi: 172.16/12 only")
check(!WifiTransport.isLocal("relay.damus.io") && !WifiTransport.isLocal("8.8.8.8") && !WifiTransport.isLocal("favillakey.io"), "Wi-Fi: internet hosts refused")
UserDefaults.standard.removeObject(forKey: WifiTransport.hostKey)
check(WifiTransport.target(for: "192.168.1.9") == "192.168.1.9" && WifiTransport.target(for: "example.com") == nil, "Wi-Fi: page host used only when local")
UserDefaults.standard.set("192.168.20.24", forKey: WifiTransport.hostKey)
check(WifiTransport.target(for: "key.bluetooth") == "192.168.20.24" && WifiTransport.target(for: "relay.damus.io") == "192.168.20.24", "Wi-Fi: a non-local page host goes to the saved KEY address, never the internet")
UserDefaults.standard.removeObject(forKey: WifiTransport.hostKey)

extension Optional {
    struct Nil: Error {}
    func unwrap() throws -> Wrapped { guard let v = self else { throw Nil() }; return v }
}

// --- App channel (9g-9j): the firmware's tests/app_chan_vector.py and a pairing vector
let chK = Data((0..<32).map { UInt8($0) }), chCid = hex("0102030405060708")
let chCreds = Credentials(key: chK, clientId: chCid)
let chSite = Data("github.com".utf8)
let chFill = AppChannel.request(AppChannel.cFill, chCreds, ctr: 1, body: Data([UInt8(chSite.count)]) + chSite + Data([0]))
check(hx(chFill) == "340102030405060708010000000a6769746875622e636f6d00265b05341089fecfecbf38a64ad8cd9b", "channel: FILL request matches the firmware vector")
let chReps = AppChannel.reports(chFill)
check(chReps.count == 1 && hx(chReps[0]) == "102900340102030405060708010000000a6769746875622e636f6d00265b05341089fecfecbf38a64ad8cd9b0000000000000000000000000000000000000000", "channel: FILL as one 64-byte report")
do {
    let a = try AppChannel.open(hex("b301020304050607080100000028d19f4993eeb43c3a8a7c7b42a0f5460751b18c72ecec29f5e994ab94"), chCreds)
    check(a.rsp == 0xB3 && a.ctr == 1, "channel: login answer type and counter")
    let l = try Ctap.parseFill(a.body)
    check(l.user == "josh" && l.password == "secret", "channel: login answer decrypts to josh / secret")
} catch { check(false, "channel: open threw \(error)") }
var chBad = [UInt8](hex("b301020304050607080100000028d19f4993eeb43c3a8a7c7b42a0f5460751b18c72ecec29f5e994ab94")); chBad[14] ^= 1
check((try? AppChannel.open(Data(chBad), chCreds)) == nil, "channel: a changed answer fails the mac")
do { _ = try AppChannel.open(hex("bf3408"), chCreds); check(false, "unmac'd error should throw") }
catch AppChannel.Failure.unauthenticated(let c, let st) { check(c == 0x34 && st == 0x08, "channel: [0xBF][cmd][status] without a mac") }
catch { check(false, "channel: wrong error \(error)") }
check(hx(AppChannel.request(AppChannel.cTime, chCreds, ctr: 2, body: AppChannel.timeBody(Date(timeIntervalSince1970: 1794000000)))) == "39010203040506070802000000000000006aee4480813ed68562427b5fe1b240e6ed18367a", "channel: TIME request (time big endian)")
check(hx(AppChannel.request(AppChannel.cList, chCreds, ctr: 3, body: AppChannel.listBody(start: 12))) == "37010203040506070803000000000ccdcd0ca6e038e4d7eca92ee3fa998c03", "channel: LIST request (start big endian)")
do {
    let a = try AppChannel.open(hex("b7010203040506070804000000ecc2f50768fb54d5011dbb3f7c5ca3ba09c7144bf9e72eae"), chCreds)
    check(a.rsp == 0xB7 && hx(a.body) == "0006313233343536", "channel: OTP answer decrypts to 123456")
    let b = try AppChannel.open(hex("b6010203040506070805000000388634416e9c9536a3ea657f23b492b99746e0c4a56aee256fe01d61c8d780474c529226d5f4f5d829a7533c035b23cf96bef1437c149f6bb705e9be7ef3e1164ded441738ed50ca4cb3bcf67698baf4d358"), chCreds)
    check(b.body == Data([0x00, 0x40]) + Data((0..<64).map { UInt8($0) }), "channel: a 66-byte answer decrypts across keystream blocks")
} catch { check(false, "channel: OTP/LIST open threw \(error)") }
do {   // a long message: reports and reassembly, several reports per notification
    let long = Data((0..<300).map { UInt8($0 & 0xFF) })
    let rs = AppChannel.reports(long)
    check(rs.count == 5 && rs.allSatisfy { $0.count == 64 } && rs[1][0] == 0x11 && rs[1][1] == 1, "channel: 300 bytes is 5 reports")
    var r = AppChannel.Reassembler()
    var got: [Data] = []
    for w in AppChannel.writes(long, perWrite: 2) { got += try r.feed(w) }
    check(got == [long], "channel: reassembles from multi-report notifications")
    var r2 = AppChannel.Reassembler()
    check((try? r2.feed(rs[0] + rs[2])) == nil, "channel: a skipped report is refused")
} catch { check(false, "channel: reassembly threw \(error)") }
do {   // pairing: fixed keys (scalars 0x11.. and 0x22..), nonce 00..0f; vector from the doc's formulas
    let ext = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))
    let keyP = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x22, count: 32))
    let p = AppChannel.Pairing(priv: ext, nonce: Data((0..<16).map { UInt8($0) }))
    check(hx(p.extPub) == "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794", "pairing: extPub")
    check(hx(p.commit) == "20" + "37f30e77e7bf6bb078fef09cc2d457eb6fc34ab7183fac0e6762f6d3effb2beb", "pairing: commitment")
    check(p.reveal.count == 1 + 65 + 16 && p.reveal.first == 0x22, "pairing: reveal")
    let a0 = Data([0xA0]) + keyP.publicKey.x963Representation + chCid
    let (c, code) = try p.derive(a0)
    check(hx(c.key) == "123bc42d720cc86a8479e8bd7bbc559bdf29049cf8488b8cc543a6b20de16884" && c.clientId == chCid, "pairing: channel key")
    check(code == "465988" && AppChannel.spaced(code) == "465 988", "pairing: 6-digit code")
} catch { check(false, "pairing threw \(error)") }

do {   // the firmware's own pairing vector (tests/app_pair_vector.py, issue #2, 7 Nov 2026), byte for byte
    let ext = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))
    let keyP = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x22, count: 32))
    let p = AppChannel.Pairing(priv: ext, nonce: Data((0x30..<0x40).map { UInt8($0) }))
    check(hx(p.commit) == "20854b2f2a3661f931f55ebc63ad519fcd2a4da9ab460c1ac5aafa054d2cbcebf5", "pair vector: 1. PAIR_COMMIT")
    let a0 = hex("a004d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285a1a2a3a4a5a6a7a8")
    check(a0 == Data([0xA0]) + keyP.publicKey.x963Representation + hex("a1a2a3a4a5a6a7a8"), "pair vector: 2. R_PAIR_KEY is the KEY's public key and client id")
    check(hx(p.reveal) == "22040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794303132333435363738393a3b3c3d3e3f", "pair vector: 3. PAIR_REVEAL")
    let (c, code) = try p.derive(a0)
    check(hx(c.key) == "123bc42d720cc86a8479e8bd7bbc559bdf29049cf8488b8cc543a6b20de16884", "pair vector: K")
    check(hx(c.clientId) == "a1a2a3a4a5a6a7a8", "pair vector: clientId")
    check(AppChannel.spaced(code) == "465 988", "pair vector: code 465 988")
    let done = try AppChannel.open(hex("a1a1a2a3a4a5a6a7a80000000000f25fd59a50bed1987b5e5dd15c8b68d3"), c)
    check(done.rsp == AppChannel.rPairDone && done.ctr == 0 && done.body == Data([0x00]), "pair vector: 4. R_PAIR_DONE paired, mac checks with K")
    check(hx(AppChannel.request(AppChannel.cHello, c, ctr: 1)) == "30a1a2a3a4a5a6a7a8010000007de3085ed4b493e255cfa9a3d2a6090c", "pair vector: 5. HELLO ctr 1")
    var tampered = [UInt8](hex("a1a1a2a3a4a5a6a7a80000000000f25fd59a50bed1987b5e5dd15c8b68d3")); tampered[13] = 0x0B
    check((try? AppChannel.open(Data(tampered), c)) == nil, "pair vector: R_PAIR_DONE with a changed status fails the mac")
} catch { check(false, "pair vector threw \(error)") }

do {   // NOSTR over Bluetooth (9k): the API request and its encrypted answer on the app channel
    let r = ApiRequest(method: "POST", host: "key.bluetooth", path: "/api/sign",
                       headers: ["X-Favilla-Session": "ab", "X-Favilla-Ctr": "7"], body: Data("{}".utf8), timeout: 10)
    let body = try ApiWire.encode(r).unwrap()
    check(hx(AppChannel.request(AppChannel.cApi, chCreds, ctr: 9, body: body)) == "3a0102030405060708090000000209002f6170692f7369676e0201020061620301003702007b7db3a5818f1917445f2fb1a6c10a87a601",
          "API on the channel: 0x3A request with mac (firmware app_chan_vector functions)")
    let a = try AppChannel.open(hex("b80102030405060708090000004304df428bf8220c3b568bdb6a78dd36c4129891e9aefc"), chCreds)
    check(a.rsp == AppChannel.rApi && a.ctr == 9, "API answer: 0xB8, counter echoed")
    check(ApiWire.decodeAnswer(a.body) == ApiResponse(status: 200, contentType: "application/json", body: Data("{}".utf8)), "API answer: decrypts to 200 JSON {}")
    // A 20 KB body: over 255 reports, so the index wraps from 255 to 0.
    var big = r; big.body = Data((0..<20_000).map { UInt8($0 & 0xFF) })
    let msg = AppChannel.request(AppChannel.cApi, chCreds, ctr: 10, body: try ApiWire.encode(big).unwrap())
    let reps = AppChannel.reports(msg, limit: AppChannel.msgMaxApi)
    check(reps.count == 1 + Int((Double(msg.count - 61) / 62).rounded(.up)) && reps[255][1] == 255 && reps[256][1] == 0 && reps[257][1] == 1, "API: report index wraps 255 to 0")
    var ra = AppChannel.Reassembler(limit: AppChannel.msgMaxApi)
    var got: [Data] = []
    for w in AppChannel.writes(msg, perWrite: 8, limit: AppChannel.msgMaxApi) { got += try ra.feed(w) }
    check(got == [msg], "API: 20 KB message reassembles across the wrap")
    var small = AppChannel.Reassembler()
    check((try? small.feed(reps[0])) == nil, "API: the default reassembler still refuses messages over 1088 bytes")
} catch { check(false, "API channel threw \(error)") }

do {   // issue #9: a 1.2 KB answer in three notifications (MTU 527: 8 + 8 + 4 reports), the log, the keystream limit
    let body = Data([0xC8, 0x00, 0x01]) + Data([0x90, 0x04]) + Data(repeating: 0x41, count: 1168)   // 200, JSON, 1168 bytes
    var m = Data([AppChannel.rApi]) + chCreds.clientId + Data([9, 0, 0, 0]) + AppChannel.keystream(body, rsp: AppChannel.rApi, ctr: 9, chCreds)
    m += AppChannel.h(chCreds.key, Data("RSP".utf8) + m).prefix(16)
    check(m.count == 1202, "issue #9: the answer is 1202 bytes, as on the bench")
    let reps = AppChannel.reports(m, limit: AppChannel.msgMaxApi)
    check(reps.count == 20, "issue #9: 20 reports")
    let notes = [Data(reps[0..<8].joined()), Data(reps[8..<16].joined()), Data(reps[16..<20].joined())]
    check(LinkLog.describe(notes[0]) == "start 1202, cont 1-7" && LinkLog.describe(notes[2]) == "cont 16-19", "log: notification report headers")
    var ra = AppChannel.Reassembler(limit: AppChannel.msgMaxApi)
    var got: [Data] = []
    for (i, n) in notes.enumerated() {
        got += try ra.feed(n)
        if i == 0 { check(ra.progress.have == 495 && ra.progress.want == 1202, "log: progress after the first notification") }
    }
    check(got == [m], "issue #9: three notifications reassemble to the answer")
    let a = try AppChannel.open(got[0], chCreds)
    check(a.rsp == AppChannel.rApi && a.ctr == 9 && ApiWire.decodeAnswer(a.body)?.body.count == 1168, "issue #9: opens and decodes to 200 with 1168 bytes")
    var big = Data([AppChannel.rApi]) + chCreds.clientId + Data([9, 0, 0, 0]) + Data(count: AppChannel.keystreamMax + 1)
    big += AppChannel.h(chCreds.key, Data("RSP".utf8) + big).prefix(16)
    check((try? AppChannel.open(big, chCreds)) == nil, "issue #9: an encrypted body over 8160 bytes is refused, not a crash")
    do { _ = try AppChannel.open(big, chCreds) } catch { check(error as? AppChannel.Failure == .tooLong, "issue #9: refused as tooLong") }
    check(LinkLog.path(of: try ApiWire.encode(ApiRequest(method: "GET", host: "", path: "/api/pair/sas?pair_id=7", headers: [:], body: Data(), timeout: 5)).unwrap()) == "GET /api/pair/sas", "log: path without its query")
} catch { check(false, "issue #9 tests threw \(error)") }

do {   // answer bodies: OTP and LIST
    check((try? AppChannel.parseOtp(hex("0006313233343536"))) == "123456", "OTP body: the code")
    check((try? AppChannel.parseOtp(hex("03"))) == nil, "OTP body: no code saved throws")
    check((try? AppChannel.parseOtp(hex("0006313233"))) == nil, "OTP body: short throws")
    var l = hex("00000203")                                   // total 2, count 2
    l += hex("00") + Data([10]) + Data("github.com".utf8) + Data([4]) + Data("josh".utf8)
    l += hex("01") + Data([11]) + Data("webauthn.io".utf8) + Data([2]) + Data("jc".utf8)
    l += hex("22") + Data(repeating: 0xAB, count: 34) + Data([3]) + hex("010203")
    l += hex("00")
    l[3] = 2
    let page = try AppChannel.parseList(l)
    check(page.total == 2 && !page.more && page.entries.count == 2, "LIST body: header and more")
    check(page.entries[0] == AppChannel.ListEntry(passkey: false, site: "github.com", user: "josh"), "LIST body: password entry")
    check(page.entries[1].passkey && page.entries[1].site == "webauthn.io" && page.entries[1].credentialID == Data(repeating: 0xAB, count: 34) && page.entries[1].userHandle == hex("010203"), "LIST body: passkey entry")
    check((try? AppChannel.parseList(l.dropLast())) == nil, "LIST body: missing more byte throws")
    check((try? AppChannel.parseList(hex("02"))) == nil, "LIST body: refused throws")
    check((try? AppChannel.parseList(hex("0000000001"))).map { $0.entries.isEmpty && $0.more } == true, "LIST body: empty page with more")
} catch { check(false, "answer bodies threw \(error)") }


// MARK: - Bluetooth bunker (issue #11, proposed bytes)

do {
    let ev1 = Data(#"["EVENT",{"id":"aa","kind":24133}]"#.utf8)
    let ev2 = Data(#"["EVENT",{"id":"bb","kind":24133}]"#.utf8)
    var b = Data([0x01, 0x02])
    b.append(UInt8(ev1.count & 0xFF)); b.append(UInt8(ev1.count >> 8)); b.append(ev1)
    b.append(UInt8(ev2.count & 0xFF)); b.append(UInt8(ev2.count >> 8)); b.append(ev2)
    check(Bunker.decodeReplies(b) == Bunker.Replies(more: true, messages: [ev1, ev2]), "bunker: 0xB9 with two replies and more-to-come")
    check(Bunker.decodeReplies(hex("0000")) == Bunker.Replies(more: false, messages: []), "bunker: 0xB9 empty, nothing more")
    check(Bunker.decodeReplies(b.dropLast()) == nil, "bunker: 0xB9 short reply refused")
    check(Bunker.decodeReplies(b + hex("00")) == nil, "bunker: 0xB9 trailing byte refused")
    check(Bunker.decodeReplies(hex("000100000000")) == nil, "bunker: 0xB9 zero-length reply refused")

    var info = Data(repeating: 0xDC, count: 32) + Data([2])
    for h in ["relay.favillakey.io", "nos.lol"] { info.append(UInt8(h.utf8.count)); info.append(Data(h.utf8)) }
    check(Bunker.decodeInfo(info) == Bunker.Info(pubkey: String(repeating: "dc", count: 32), relays: ["wss://relay.favillakey.io", "wss://nos.lol"]), "bunker: 0xBA pubkey and relays")
    check(Bunker.decodeInfo(Data(repeating: 0xDC, count: 32) + hex("00")) == nil, "bunker: 0xBA with no relays refused")
    var bad = Data(repeating: 0xDC, count: 32) + Data([1]); bad.append(9); bad.append(Data("evil host".utf8))
    check(Bunker.decodeInfo(bad) == nil, "bunker: 0xBA host with a space refused")
    check(Bunker.decodeInfo(info + hex("00")) == nil, "bunker: 0xBA trailing byte refused")

    // serve(): two requests, the second needs an approval on the KEY; the poll brings its reply.
    final class FakeKey: ChannelCaller, @unchecked Sendable {
        var sent: [(UInt8, Data)] = []
        var answers: [Data]
        init(_ a: [Data]) { answers = a }
        func request(_ cmd: UInt8, _ body: Data, timeout: TimeInterval) async throws -> AppChannel.Answer {
            sent.append((cmd, body))
            return AppChannel.Answer(rsp: Bunker.rNip46, ctr: 1, body: answers.isEmpty ? hex("0000") : answers.removeFirst())
        }
    }
    func one(_ m: Data, more: Bool) -> Data { var d = Data([more ? 1 : 0, 1, UInt8(m.count & 0xFF), UInt8(m.count >> 8)]); d.append(m); return d }
    let fk = FakeKey([one(ev1, more: false), hex("0100"), hex("0100"), one(ev2, more: false)])
    final class Box: @unchecked Sendable { var o = Bunker.Outcome() }
    let box = Box()
    let done = DispatchSemaphore(value: 0)
    Task {
        box.o = await Bunker.serve([("r1", Data("{}".utf8)), ("r2", Data("{}".utf8))], via: fk, relays: [], until: Date().addingTimeInterval(10))
        done.signal()
    }
    done.wait()
    var out = box.o
    check(fk.sent.map { $0.0 } == [Bunker.cNip46, Bunker.cNip46, Bunker.cPoll, Bunker.cPoll], "bunker: serve sends both requests, then polls while more is set")
    check(out.taken == 2 && out.replies == 2 && !out.waiting && out.error == nil, "bunker: serve collects the late reply")
    check(Bunker.seen("r1") && Bunker.seen("r2"), "bunker: served requests are marked seen")

    // 10p vectors (tests/app_chan_vector.py): NIP46_POLL at ctr 3, and the empty answer with more to come.
    check(hx(AppChannel.request(Bunker.cPoll, chCreds, ctr: 3, body: Data())) == "3c01020304050607080300000041748c20e5ed9f20c16e01769edebd5c", "bunker: NIP46_POLL matches the firmware vector")
    if let a = try? AppChannel.open(hex("b90102030405060708030000000100e0a682a02d7adeb6c2d4c79ecb3b7317"), chCreds) {
        check(a.rsp == Bunker.rNip46 && Bunker.decodeReplies(a.body) == Bunker.Replies(more: true, messages: []), "bunker: the firmware's empty 0xB9 reads as more to come")
    } else { check(false, "bunker: the firmware's 0xB9 vector opens") }

    // S_BUSY: the request and the ones after it wait; polling continues; then they go again.
    final class Busy: ChannelCaller, @unchecked Sendable {
        var sent: [UInt8] = []; var n = 0
        func request(_ cmd: UInt8, _ body: Data, timeout: TimeInterval) async throws -> AppChannel.Answer {
            sent.append(cmd); n += 1
            if cmd == Bunker.cNip46 && n == 1 { return AppChannel.Answer(rsp: AppChannel.rErr, ctr: 1, body: Data([0x06])) }
            return AppChannel.Answer(rsp: Bunker.rNip46, ctr: 1, body: hex("0000"))
        }
    }
    let bz = Busy(), busyDone = DispatchSemaphore(value: 0)
    Task {
        box.o = await Bunker.serve([("b1", Data("{}".utf8)), ("b2", Data("{}".utf8))], via: bz, relays: [], until: Date().addingTimeInterval(10))
        busyDone.signal()
    }
    busyDone.wait()
    check(bz.sent == [Bunker.cNip46, Bunker.cPoll, Bunker.cNip46, Bunker.cNip46] && box.o.taken == 2 && box.o.later.isEmpty, "bunker: S_BUSY waits, polls, then sends both again")

    let refused = DispatchSemaphore(value: 0)
    final class Locked: ChannelCaller {
        func request(_ cmd: UInt8, _ body: Data, timeout: TimeInterval) async throws -> AppChannel.Answer { AppChannel.Answer(rsp: AppChannel.rErr, ctr: 1, body: Data([0x05])) }
    }
    Task {
        box.o = await Bunker.serve([("r3", Data("{}".utf8))], via: Locked(), relays: [], until: Date().addingTimeInterval(5))
        refused.signal()
    }
    refused.wait()
    out = box.o
    check(out.taken == 0 && out.error?.contains("locked") == true && !Bunker.seen("r3"), "bunker: a locked KEY is reported and the request kept for later")
}

print(failures == 0 ? "ALL PASSED" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
