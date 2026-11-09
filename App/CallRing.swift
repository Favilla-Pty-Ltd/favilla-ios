// CallRing.swift - incoming Nostr calls ring like phone calls (10 Nov 2026).
//
// Josh: "make it so phone and video calls push to the phone and ring even if
// not in the app". The push bridge watches the relays for the call wraps the
// PWA uses (kind 21059, NIP-AC) addressed to the owner and sends a VoIP push.
// iOS wakes Favilla for it, Favilla must report an incoming call to CallKit at
// once (the full-screen ring, lock screen, ringtone), and when you answer, the
// Nostr client opens and accepts the call in the PWA.
//
// The bridge can't read the wrap (NIP-44 to the owner's key, decrypted by the
// KEY), so the ring starts as "Nostr call"; the PWA gives the caller's name
// once the KEY has decrypted the offer (bridge.js reports the PWA's banner).
// A wrap that turns out not to be an offer (a hang-up, a late answer) ends the
// reported call straight away, which iOS allows.

import AVFoundation
import CallKit
import PushKit
import UIKit

@MainActor
final class CallRing: NSObject, ObservableObject {
    static let shared = CallRing()
    static let group = "group.io.favillakey.app"

    private var registry: PKPushRegistry?
    private let provider: CXProvider
    private let controller = CXCallController()
    private(set) var current: UUID?          // the call CallKit is showing
    private var answered = false
    private var pwaIncoming = false          // the PWA has the offer and is showing its banner
    private var pwaLive = false              // the PWA is in a call (ours or outgoing)
    private var endTimer: Timer?
    @Published private(set) var voipToken = ""
    @Published private(set) var log: [String] = []

    /// What the app asks the PWA to do when you answer or decline on the lock
    /// screen; NostrClientView runs it through bridge.js.
    var onCommand: ((String) -> Void)?

    private override init() {
        let c = CXProviderConfiguration()
        c.supportsVideo = true
        c.maximumCallGroups = 1
        c.maximumCallsPerCallGroup = 1
        c.supportedHandleTypes = [.generic]
        c.includesCallsInRecents = false
        if let i = UIImage(named: "CallIcon") { c.iconTemplateImageData = i.pngData() }
        provider = CXProvider(configuration: c)
        super.init()
        provider.setDelegate(self, queue: .main)
    }

    /// App launch: register for VoIP pushes (no permission prompt; iOS gives a
    /// token when the app has the voip background mode).
    func start() {
        guard registry == nil else { return }
        let r = PKPushRegistry(queue: .main)
        r.delegate = self
        r.desiredPushTypes = [.voIP]
        registry = r
        voipToken = UserDefaults(suiteName: CallRing.group)?.string(forKey: "voipToken") ?? ""
    }

    private func note(_ s: String) {
        log.insert(ISO8601DateFormatter().string(from: Date()) + " " + s, at: 0)
        if log.count > 40 { log.removeLast() }
        Bunker.log("call: " + s)
    }

    // MARK: - From the PWA (via bridge.js)

    /// The PWA is showing its incoming-call banner: name the caller on the ring,
    /// or start a ring if none is up (the app was open and no push came first).
    func pwaIncoming(name: String, video: Bool) {
        pwaIncoming = true
        let u = CXCallUpdate()
        u.remoteHandle = CXHandle(type: .generic, value: name)
        u.localizedCallerName = name
        u.hasVideo = video
        u.supportsHolding = false
        u.supportsGrouping = false
        u.supportsUngrouping = false
        u.supportsDTMF = false
        if let c = current {
            provider.reportCall(with: c, updated: u)
            note("caller: \(name)")
            if answered { onCommand?("accept") }      // answered on the lock screen before the client had the offer
        } else {
            let id = UUID()
            current = id
            answered = false
            provider.reportNewIncomingCall(with: id, update: u) { [weak self] e in
                if let e { self?.note("CallKit refused the ring: \(e.localizedDescription)"); self?.current = nil }
            }
            note("ringing (from the app): \(name)")
        }
        endTimer?.invalidate()
    }

    /// The PWA's call state changed: "connecting"/"connected" or "idle".
    func pwaState(_ phase: String) {
        let live = phase != "idle" && phase != "incoming"
        if live != pwaLive {
            pwaLive = live
            Task { await Bunker.inCall(live) }
        }
        if phase == "incoming" { return }
        if live, let c = current {
            if !answered { provider.reportOutgoingCall(with: c, connectedAt: nil) }    // picked up in the PWA itself
            answered = true
            return
        }
        if phase == "idle" {
            pwaIncoming = false
            end(.remoteEnded)
        }
    }

    private func end(_ why: CXCallEndedReason) {
        guard let c = current else { return }
        current = nil
        endTimer?.invalidate()
        provider.reportCall(with: c, endedAt: nil, reason: why)
        note("ended (\(why.rawValue))")
    }

    // MARK: - CallKit

    /// A VoIP push: ring at once (iOS requires it), as "Nostr call" until the PWA names the caller.
    fileprivate func ring(from payload: [AnyHashable: Any], done: @escaping () -> Void) {
        guard current == nil else { done(); return }   // a wrap for the call already ringing or live
        if pwaLive { done(); return }
        let id = UUID()
        current = id
        answered = false
        let u = CXCallUpdate()
        u.remoteHandle = CXHandle(type: .generic, value: "Nostr call")
        u.localizedCallerName = "Nostr call"
        u.hasVideo = false
        u.supportsHolding = false
        u.supportsGrouping = false
        u.supportsUngrouping = false
        u.supportsDTMF = false
        provider.reportNewIncomingCall(with: id, update: u) { [weak self] e in
            if let e { self?.note("CallKit refused the ring: \(e.localizedDescription)"); self?.current = nil }
            done()
        }
        note("ringing (VoIP push)")
        // The PWA has 25 s to confirm there is a call to take (the wrap was an
        // offer and the KEY decrypted it). A hang-up or stray wrap, or a KEY out
        // of reach, ends the ring then.
        endTimer?.invalidate()
        endTimer = Timer.scheduledTimer(withTimeInterval: 25, repeats: false) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.current != nil, !self.pwaIncoming, !self.pwaLive else { return }
                self.note("no offer reached the client in time: ending the ring")
                self.end(.unanswered)
            }
        }
        NotificationCenter.default.post(name: CallRing.wake, object: nil)
    }

    /// Posted when a ring starts from a push: the client should connect to the KEY and the relays now.
    static let wake = Notification.Name("CallRing.wake")
}

// MARK: - PushKit

extension CallRing: PKPushRegistryDelegate {
    func pushRegistry(_ r: PKPushRegistry, didUpdate credentials: PKPushCredentials, for type: PKPushType) {
        let hex = credentials.token.map { String(format: "%02x", $0) }.joined()
        voipToken = hex
        UserDefaults(suiteName: CallRing.group)?.set(hex, forKey: "voipToken")
        note("VoIP token ready")
        Task { await BunkerService.shared.registerPush() }
    }

    func pushRegistry(_ r: PKPushRegistry, didInvalidatePushTokenFor type: PKPushType) {
        voipToken = ""
        UserDefaults(suiteName: CallRing.group)?.removeObject(forKey: "voipToken")
    }

    func pushRegistry(_ r: PKPushRegistry, didReceiveIncomingPushWith payload: PKPushPayload, for type: PKPushType, completion: @escaping () -> Void) {
        guard type == .voIP, let fv = payload.dictionaryPayload["fv"] as? [String: Any], fv["call"] != nil else {
            // Not a call: iOS still wants a call reported for every VoIP push. Report and end.
            let id = UUID()
            provider.reportNewIncomingCall(with: id, update: CXCallUpdate()) { _ in
                self.provider.reportCall(with: id, endedAt: nil, reason: .failed)
                completion()
            }
            return
        }
        if let at = fv["at"] as? Int, Date().timeIntervalSince1970 - Double(at) > 60 {
            // A ring that old is over (offers go stale at 60 s in the PWA).
            let id = UUID()
            provider.reportNewIncomingCall(with: id, update: CXCallUpdate()) { _ in
                self.provider.reportCall(with: id, endedAt: nil, reason: .unanswered)
                completion()
            }
            note("stale call push ignored")
            return
        }
        ring(from: payload.dictionaryPayload, done: completion)
    }
}

// MARK: - CXProviderDelegate

extension CallRing: CXProviderDelegate {
    func providerDidReset(_ provider: CXProvider) {
        current = nil
        onCommand?("hangup")
    }

    func provider(_ provider: CXProvider, perform action: CXAnswerCallAction) {
        answered = true
        note("answered")
        onCommand?("accept")
        action.fulfill()
    }

    func provider(_ provider: CXProvider, perform action: CXEndCallAction) {
        let wasAnswered = answered
        note(wasAnswered ? "hung up" : "declined")
        onCommand?(wasAnswered ? "hangup" : "decline")
        current = nil
        endTimer?.invalidate()
        action.fulfill()
    }

    func provider(_ provider: CXProvider, perform action: CXSetMutedCallAction) {
        onCommand?(action.isMuted ? "mute" : "unmute")
        action.fulfill()
    }

    func provider(_ provider: CXProvider, didActivate audioSession: AVAudioSession) {
        note("audio session active")
    }
}
