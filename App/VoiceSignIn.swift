import SwiftUI
import Speech
import AVFoundation

// Voice sign-in in VAULT (KEY 11gk, firmware issue #90). The owner says "log
// into Forge PC"; the name goes to the KEY (TYPE_LOGIN 0x51), which finds the
// login, asks for ENTER, and types it on the computer its USB cable is in.
// Speech is recognised on this iPhone only (requiresOnDeviceRecognition): a
// login's name never goes to a server, and there is no fallback to one. The
// app does no matching and never hears the login.

/// The microphone and Apple's on-device recogniser, for one utterance.
final class VoiceListener: ObservableObject {
    @Published var heard = ""
    @Published var listening = false

    private let engine = AVAudioEngine()
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private var quiet: DispatchWorkItem?
    private var limit: DispatchWorkItem?
    private var tapped = false
    private var finished = true
    private var done: (String) -> Void = { _ in }
    private var fail: (String) -> Void = { _ in }

    static let offDevice = "This iPhone can't recognise speech on the device for its current language. Favilla never sends your voice to a server, so voice sign-in isn't available. Turning on Dictation for the language in iPhone Settings > General > Keyboard may add it."

    func start(done: @escaping (String) -> Void, fail: @escaping (String) -> Void) {
        self.done = done; self.fail = fail
        finished = false
        heard = ""
        SFSpeechRecognizer.requestAuthorization { status in
            DispatchQueue.main.async {
                guard status == .authorized else {
                    self.end(nil, "Speech recognition is off for Favilla. Turn it on in iPhone Settings > Favilla > Speech Recognition."); return
                }
                AVAudioApplication.requestRecordPermission { ok in
                    DispatchQueue.main.async {
                        guard ok else { self.end(nil, "The microphone is off for Favilla. Turn it on in iPhone Settings > Favilla > Microphone."); return }
                        self.listen()
                    }
                }
            }
        }
    }

    private func listen() {
        guard !finished else { return }
        guard let rec = SFSpeechRecognizer() ?? SFSpeechRecognizer(locale: Locale(identifier: "en-US")), rec.isAvailable, rec.supportsOnDeviceRecognition else {
            end(nil, VoiceListener.offDevice); return
        }
        let rq = SFSpeechAudioBufferRecognitionRequest()
        rq.requiresOnDeviceRecognition = true      // never a server (issue #90)
        rq.shouldReportPartialResults = true
        rq.taskHint = .search
        request = rq
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.record, mode: .measurement, options: .duckOthers)
            try session.setActive(true, options: .notifyOthersOnDeactivation)
            let input = engine.inputNode
            let format = input.outputFormat(forBus: 0)
            guard format.sampleRate > 0, format.channelCount > 0 else { end(nil, "The microphone isn't available right now."); return }
            input.installTap(onBus: 0, bufferSize: 1024, format: format) { buffer, _ in rq.append(buffer) }
            tapped = true
            engine.prepare()
            try engine.start()
        } catch {
            end(nil, "The microphone couldn't be started. Try again."); return
        }
        listening = true
        task = rec.recognitionTask(with: rq) { result, error in
            DispatchQueue.main.async {
                guard !self.finished else { return }
                if let r = result {
                    self.heard = r.bestTranscription.formattedString
                    if r.isFinal { self.end(self.heard, nil); return }
                    self.restartQuiet(1.4)       // a pause after speech ends it
                } else if error != nil {
                    self.heard.isEmpty ? self.end(nil, "Nothing was heard. Try again.") : self.end(self.heard, nil)
                }
            }
        }
        restartQuiet(8)                          // nothing said at all
        // A room that is never quiet: take what has been heard after 12 s.
        let cap = DispatchWorkItem { [weak self] in self?.finishNow() }
        limit = cap
        DispatchQueue.main.asyncAfter(deadline: .now() + 12, execute: cap)
    }

    private func restartQuiet(_ s: TimeInterval) {
        quiet?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let self, !self.finished else { return }
            self.heard.isEmpty ? self.end(nil, "Nothing was heard. Try again.") : self.end(self.heard, nil)
        }
        quiet = w
        DispatchQueue.main.asyncAfter(deadline: .now() + s, execute: w)
    }

    /// Take what has been heard so far.
    func finishNow() {
        guard !finished else { return }
        heard.isEmpty ? end(nil, "Nothing was heard. Try again.") : end(heard, nil)
    }

    /// Closing the sheet: stop, tell no one.
    func cancel() { done = { _ in }; fail = { _ in }; end(nil, nil) }

    private func end(_ text: String?, _ why: String?) {
        guard !finished else { return }
        finished = true
        quiet?.cancel(); quiet = nil
        limit?.cancel(); limit = nil
        if engine.isRunning { engine.stop() }
        if tapped { engine.inputNode.removeTap(onBus: 0); tapped = false }
        request?.endAudio(); request = nil
        task?.cancel(); task = nil
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        listening = false
        if let text { done(text) } else if let why { fail(why) }
    }
}

struct VoiceSignInSheet: View {
    @ObservedObject var model: AccountsModel
    var onClose: () -> Void

    enum Step: Equatable {
        case listening
        case onKey(String)            // the name sent; the KEY is asking
        case ended(String, Bool)      // what happened, and whether it was typed
    }
    @State private var step: Step = .listening
    @State private var name = ""
    @StateObject private var ears = VoiceListener()

    private var headline: String {
        switch step {
        case .listening: return "Say the login's name"
        case .onKey: return "Check the KEY"
        case .ended(_, let typed): return typed ? "Typed" : "Not typed"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Lockup(mark: 22, word: 15)
                Spacer()
                Button("Close") { ears.cancel(); onClose() }.font(Brand.body).foregroundStyle(Brand.grey).frame(minHeight: 44)
            }
            Text(headline).font(Brand.headline).foregroundStyle(Brand.ink)

            VStack(alignment: .leading, spacing: 8) {
                Text(step == .listening ? "LISTENING" : "HEARD").font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    if step == .listening {
                        Image(systemName: "mic.fill").font(.system(size: 20, weight: .semibold)).foregroundStyle(Brand.brass)
                    }
                    Text(shownName).font(Brand.font(24, .bold)).foregroundStyle(shownName == placeholder ? Brand.faint : Brand.ink)
                        .lineLimit(2).minimumScaleFactor(0.6)
                }
                .frame(minHeight: 44, alignment: .leading)
            }
            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 14))

            switch step {
            case .listening:
                Text("For example: \"log into Forge PC\". It stops listening when you stop talking. Your voice is turned into text on this iPhone only. The KEY finds the login and types it on the computer its USB cable is in.")
                    .font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            case .onKey:
                WaitCard(title: "Check the KEY", detail: "Pick the login on the KEY and press ENTER. It types it on the computer its USB cable is in. Hold ENTER to press Enter after it.")
            case .ended(let text, let typed):
                Text(text).font(Brand.body).foregroundStyle(typed ? Brand.ink : Brand.danger).fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)

            switch step {
            case .listening, .onKey:
                EmptyView()          // listening ends by itself (28 Nov ruling)
            case .ended:
                BrandButton(title: "SAY IT AGAIN", filled: true) { begin() }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg.ignoresSafeArea())
        .preferredColorScheme(.dark)
        .onAppear { begin() }
        .onDisappear { ears.cancel() }
    }

    private let placeholder = "…"
    private var shownName: String {
        switch step {
        case .listening: return ears.heard.isEmpty ? placeholder : ears.heard
        default: return name
        }
    }

    private func begin() {
        name = ""
        step = .listening
        if let d = Demo.mode {                   // sample screens, no microphone
            ears.heard = "Log into Forge PC"
            if d == "vault-voice-key" { name = "Forge PC"; step = .onKey("Forge PC") }
            return
        }
        ears.start(done: { heard in
            guard let n = AppChannel.spokenName(heard) else { step = .ended("No name was heard. Try again.", false); return }
            name = n
            step = .onKey(n)
            Task {
                let r = await model.typeLogin(n)
                if case .onKey(let now) = step, now == n { step = .ended(r.text, r.typed) }
            }
        }, fail: { why in
            step = .ended(why, false)
        })
    }
}
