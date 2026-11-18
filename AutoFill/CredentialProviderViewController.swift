// CredentialProviderViewController.swift - the AutoFill extension.
//
// Passwords (KEY 9c): ask the KEY for the site's login (FILL on 8F1A0003, answer
// on 8F1A0004); the owner picks it on the KEY and presses ENTER; hand it to iOS
// as an ASPasswordCredential and keep nothing.
//
// Passkeys (KEY 9a, favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md): sign-in
// sends CTAP2 getAssertion and hands the KEY's signature to iOS; creation sends
// makeCredential and hands iOS the attestation object (as "none").
//
// One-time codes (KEY 9i, iOS 18 and later): OTP on the app channel; the owner
// picks the code on the KEY; hand iOS the digits as an ASOneTimeCodeCredential.
//
// Once the app is paired with the KEY (9g), all of these go over the app
// channel (KeyLink); the KEY then refuses the raw paths.
//
// Two ways in (option 1, ruled 6 Nov 2026):
//  - the generic Favilla entry (key icon > Favilla, or Other Options): iOS says
//    only the site, the KEY shows its matches;
//  - an account iOS listed above the keyboard or first in the passkey prompt
//    (the opt-in AccountList): iOS says which account, the sheet shows it.
// Every account used while the list is on is added to it (site + username, and
// for a passkey its id and user handle; never a password).

import AuthenticationServices
import Combine
import SwiftUI

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let link = KeyLink()
    private var purpose: SheetPurpose = .password
    private var user = ""
    private var notice: String?
    private var configuring = false
    private var watch: AnyCancellable?
    private var closed = false
    private var retry: () -> Void = {}

    override func viewDidLoad() {
        super.viewDidLoad()
        show()
    }

    private func show() {
        guard isViewLoaded else { return }   // viewDidLoad shows it
        children.forEach { $0.view.removeFromSuperview(); $0.removeFromParent() }
        let onClose: () -> Void = { [weak self] in self?.close() }
        let onRetry: () -> Void = { [weak self] in self?.retry() }
        let root: AnyView = configuring
            ? AnyView(ProbeView(link: link, onClose: onClose).preferredColorScheme(.dark))
            : AnyView(SignInView(link: link, purpose: purpose, user: user, notice: notice, onRetry: onRetry,
                                 onNewPassword: purpose == .password && notice == nil ? { [weak self] in self?.startNewPassword() } : nil,
                                 onClose: onClose).preferredColorScheme(.dark))
        let host = UIHostingController(rootView: root)
        host.view.backgroundColor = UIColor(red: 14 / 255, green: 13 / 255, blue: 12 / 255, alpha: 1)
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    // MARK: - Ways in

    // Passwords, the generic entry: only the site (or app) is known.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let (site, isApp) = Self.pick(serviceIdentifiers)
        fillPassword(site: site, user: "", isApp: isApp)
    }

    /// The website iOS gave, if any (a native app linked to its site gives its
    /// domain); else, from iOS 26.2, an app not linked to a website comes as an
    /// app ID with a display name: send the name, and the KEY offers all logins
    /// when nothing matches (ruled 6 Nov 2026).
    static func pick(_ ids: [ASCredentialServiceIdentifier]) -> (String, Bool) {
        if let web = ids.first(where: { $0.type == .domain || $0.type == .URL }) { return (web.identifier, false) }
        if #available(iOS 26.2, *), let app = ids.first(where: { $0.type == .app }) {
            return (app.displayName ?? app.identifier, true)
        }
        return (ids.first?.identifier ?? "", false)
    }

    // Passkey sign-in, the generic entry (Other Options > Favilla).
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        signInWithPasskey(rp: requestParameters.relyingPartyIdentifier, user: "", clientDataHash: requestParameters.clientDataHash,
                          uv: requestParameters.userVerificationPreference, allow: requestParameters.allowedCredentials)
    }

    // One-time codes (iOS 18+): the code field's site or app.
    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let (site, isApp) = Self.pick(serviceIdentifiers)
        oneTimeCode(site: site, isApp: isApp)
    }

    // An account iOS listed: always needs the KEY, so ask for the sheet.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                          code: ASExtensionError.userInteractionRequired.rawValue))
    }

    // An account iOS listed, with the sheet.
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        if #available(iOS 18.0, *), credentialRequest.type == .oneTimeCode {
            let (site, isApp) = Self.pick([credentialRequest.credentialIdentity.serviceIdentifier])
            oneTimeCode(site: site, isApp: isApp)
            return
        }
        if let p = credentialRequest as? ASPasskeyCredentialRequest, let id = p.credentialIdentity as? ASPasskeyCredentialIdentity {
            signInWithPasskey(rp: id.relyingPartyIdentifier, user: id.userName, clientDataHash: p.clientDataHash,
                              uv: p.userVerificationPreference, allow: [id.credentialID])
        } else if let id = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity {
            let (site, isApp) = Self.pick([id.serviceIdentifier])
            fillPassword(site: site, user: id.user == AccountList.unknownUser ? "" : id.user, isApp: isApp)   // a list entry the KEY hadn't labelled: ask by site
        } else {
            notice = "iOS asked for something Favilla can't read."
            show()
        }
    }

    // Passkey creation.
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let req = registrationRequest as? ASPasskeyCredentialRequest,
              let id = req.credentialIdentity as? ASPasskeyCredentialIdentity else {
            notice = "iOS didn't send a passkey request Favilla can read."
            show()
            return
        }
        makePasskey(rp: id.relyingPartyIdentifier, user: id.userName, userHandle: id.userHandle,
                    clientDataHash: req.clientDataHash, uv: req.userVerificationPreference,
                    algorithms: req.supportedAlgorithms.map { $0.rawValue })
    }

    // MARK: - New passwords (iOS 26.2, KEY 11bi, issue #38)

    // A new-password field: strong passwords made by the KEY (GEN_PW), no sheet.
    // Apple: save nothing here; the save comes after the form is sent.
    @available(iOS 26.2, *)
    override func performWithoutUserInteraction(generatePasswordsRequest request: ASGeneratePasswordsRequest) {
        let rules = NewPassword.rules(request.passwordFieldPasswordRules)
        Task { @MainActor in
            var out: [ASGeneratedPassword] = []
            var why = ""
            if let c = Credentials.load() {
                let s = KeySession(c)
                do {
                    try await s.open(timeout: 6)
                    var kinds: [(ASGeneratedPassword.Kind, UInt8)] = [(.alphanumeric, 0x02)]
                    if rules.allowsSpecial { kinds.insert((.strong, 0x01), at: 0) }
                    for (kind, k) in kinds {
                        let a = try await s.request(AppChannel.cGenPw, NewPassword.genBody(rules, kind: k), timeout: 6)
                        if a.rsp == AppChannel.rErr { why = NewPassword.genText(a.body.first ?? 0xFF); break }
                        guard a.rsp == AppChannel.rGenPw else { why = "The KEY's answer couldn't be read."; break }
                        switch NewPassword.parseGen(a.body) {
                        case .success(let p): out.append(ASGeneratedPassword(kind: kind, value: p))
                        case .failure(.status(let st)): why = NewPassword.genText(st)
                        }
                    }
                } catch { why = "\(error)" }
                s.close()
            } else { why = "the app isn't paired" }
            LastRequest.save("Strong password for \(request.serviceIdentifier.identifier)",
                             [out.isEmpty ? "No password from the KEY: \(why)" : "\(out.count) password(s) from the KEY handed to iOS"])
            if out.isEmpty {
                self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
            } else {
                self.extensionContext.completeGeneratePasswordRequest(results: out, completionHandler: nil)
            }
        }
    }

    // iOS's save after a form: always needs the KEY's ENTER, so the sheet; except
    // a generated password just filled (wait for the form to be sent) and a login
    // the KEY itself just sent (its NEW LOGIN / NEW PASSWORD already saved it).
    @available(iOS 26.2, *)
    override func performWithoutUserInteractionIfPossible(savePasswordRequest request: ASSavePasswordRequest) {
        if request.event == .generatedPasswordFilled || alreadyOnKey(request) {
            extensionContext.completeSavePasswordRequest(completionHandler: nil)
            return
        }
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    @available(iOS 26.2, *)
    override func prepareInterface(for request: ASSavePasswordRequest) {
        if request.event == .generatedPasswordFilled || alreadyOnKey(request) {
            extensionContext.completeSavePasswordRequest(completionHandler: nil)
            return
        }
        let (site, _) = Self.pick([request.serviceIdentifier])
        let job = SaveJob(site: site, user: request.credential.user, pass: request.credential.password)
        children.forEach { $0.view.removeFromSuperview(); $0.removeFromParent() }
        let view = SaveToKeyView(job: job, onDone: { [weak self] in
            self?.closed = true
            self?.extensionContext.completeSavePasswordRequest(completionHandler: nil)
        }, onCancel: { [weak self] in
            self?.closed = true
            self?.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
        }).preferredColorScheme(.dark)
        let host = UIHostingController(rootView: view)
        host.view.backgroundColor = UIColor(red: 14 / 255, green: 13 / 255, blue: 12 / 255, alpha: 1)
        addChild(host)
        host.view.frame = self.view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        self.view.addSubview(host.view)
        host.didMove(toParent: self)
        Task { await job.run() }
    }

    @available(iOS 26.2, *)
    private func alreadyOnKey(_ r: ASSavePasswordRequest) -> Bool {
        let (site, _) = Self.pick([r.serviceIdentifier])
        return NewPassword.justFilled(site: KeyLink.cleanSite(site) ?? site, user: r.credential.user, password: r.credential.password)
    }

    // Settings > AutoFill & Passwords > Favilla: the link check (and pairing).
    override func prepareInterfaceForExtensionConfiguration() {
        configuring = true
        show()
        link.probe()
    }

    // MARK: - Passwords

    // MARK: - A new password, run by the app (18 Nov)

    private var changeJob: ChangeJob?

    /// From the sign-in sheet: stop the KEY's login picker and run the change
    /// from the phone (NewPasswordFlow.swift). The KEY only asks for ENTER.
    private func startNewPassword() {
        let site = link.site
        let host = (link.siteIsAppName ? KeyLink.cleanAppName(site) : KeyLink.cleanSite(site)) ?? site
        watch = nil
        retry = {}
        link.cancel()
        let job = ChangeJob(site: host)
        changeJob = job
        children.forEach { $0.view.removeFromSuperview(); $0.removeFromParent() }
        let view = NewPasswordView(job: job, onCancel: { [weak self] in
            guard let self, !self.closed else { return }
            self.closed = true
            job.close()
            LastRequest.save("New password for \(host)", ["closed on the sheet"])
            self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
        }).preferredColorScheme(.dark)
        let hostVC = UIHostingController(rootView: view)
        hostVC.view.backgroundColor = UIColor(red: 14 / 255, green: 13 / 255, blue: 12 / 255, alpha: 1)
        addChild(hostVC)
        hostVC.view.frame = self.view.bounds
        hostVC.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        self.view.addSubview(hostVC.view)
        hostVC.didMove(toParent: self)
        watch = job.$phase.sink { [weak self] p in
            guard let self, case .done(let change) = p, let r = job.result, !self.closed else { return }
            self.closed = true
            LastRequest.save("New password for \(host)", [change ? "changed on the KEY, old one kept; filled and copied for a confirm box" : "new login saved on the KEY; filled and copied for a confirm box"])
            NewPassword.recordFill(site: host, user: r.user, password: r.password)   // iOS's own save afterwards is skipped
            // A moment to read where the confirm box's copy is, then hand the login to iOS.
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
                self.extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: r.user, password: r.password))
            }
        }
        // The KEY's picker takes a moment to clear after the cancel.
        Task { try? await Task.sleep(nanoseconds: 500_000_000); await job.load() }
    }

    // A retype box (17 Nov bench): iOS fills a login into the form's first
    // password box only, so the confirm box stays empty. AutoFill > Passwords >
    // Favilla on that box asks for text instead: the KEY sends the login it
    // just sent ("Send again?" within 60 s) and its password goes into the box.
    @available(iOS 18.0, *)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        LastRequest.save("Text for a box (AutoFill > Passwords)", [NewPassword.lastFill() == nil ? "no login filled in the last minute" : "inserting the login just sent"])
        guard let last = NewPassword.lastFill() else {
            purpose = .password
            notice = "Fill the first password box from Favilla first. Then, within a minute, come back to this box: AutoFill, Passwords, Favilla, and press ENTER at Send again? on the KEY."
            show()
            return
        }
        fillPassword(site: last.site, user: last.user, insertText: true)
    }

    private func fillPassword(site: String, user wanted: String, isApp: Bool = false, insertText: Bool = false) {
        purpose = .password
        user = wanted
        link.site = site
        link.siteIsAppName = isApp
        link.fillUser = wanted
        show()
        let host = (isApp ? KeyLink.cleanAppName(site) : KeyLink.cleanSite(site)) ?? site
        watch = link.$outcome.sink { [weak self] o in
            guard let self, case .answer(let body)? = o else { return }
            defer { self.link.clearAnswer() }   // the password is not kept past here
            do {
                let login = try Ctap.parseFill(body)
                self.link.note("Login from the KEY (username \(login.user.isEmpty ? "empty" : "\(login.user.count) characters")); handing it to iOS")
                // The same login asked for again within a minute (a retype box,
                // which iOS won't fill: it refills the first box): also put the
                // password on the clipboard, this iPhone only, for 60 s.
                let again = !insertText && NewPassword.lastFill().map { $0.site == host && $0.user.lowercased() == login.user.lowercased() } == true
                if again {
                    UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: login.password]],
                                                  options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
                    self.link.note("Sent again within a minute: also copied for the retype box (this iPhone only, cleared in 60 s)")
                }
                LastRequest.save("Password for \(host)" + (again ? " (again: copied for the retype box)" : ""), self.link.lines)
                let cred = ASPasswordCredential(user: login.user, password: login.password)
                NewPassword.recordFill(site: host, user: login.user, password: login.password)   // iOS's save of this same login is skipped (11bi)
                self.closed = true
                if insertText, #available(iOS 18.0, *) {
                    self.extensionContext.completeRequest(withTextToInsert: login.password, completionHandler: nil)
                    return
                }
                // An app's name isn't a website iOS can list it under: list websites only.
                AccountList.record(.init(passkey: false, site: isApp ? "" : host, user: login.user)) {
                    self.extensionContext.completeRequest(withSelectedCredential: cred)
                }
            } catch Ctap.FillFailure.status(let st) {
                self.link.showFailure(Ctap.message(forFillStatus: st))
                LastRequest.save("Password for \(host)", self.link.lines)
            } catch {
                self.link.showFailure("The KEY's answer couldn't be read.")
                LastRequest.save("Password for \(host)", self.link.lines)
            }
        }
        retry = { [weak self] in self?.link.fill() }
        link.fill()
    }

    // MARK: - One-time codes

    @available(iOS 18.0, *)
    private func oneTimeCode(site: String, isApp: Bool) {
        purpose = .oneTimeCode
        user = ""
        link.site = site
        link.siteIsAppName = isApp
        link.fillUser = ""
        show()
        let host = (isApp ? KeyLink.cleanAppName(site) : KeyLink.cleanSite(site)) ?? site
        watch = link.$outcome.sink { [weak self] o in
            guard let self else { return }
            if case .failed? = o { LastRequest.save("One-time code for \(host)", self.link.lines); return }
            guard case .otp(let code)? = o else { return }
            defer { self.link.clearAnswer() }   // the code is not kept past here
            self.link.note("Code from the KEY (\(code.count) digits); handing it to iOS")
            LastRequest.save("One-time code for \(host)", self.link.lines)
            self.closed = true
            self.extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
        }
        retry = { [weak self] in self?.link.oneTimeCode() }
        link.oneTimeCode()
    }

    // MARK: - Passkeys

    private func signInWithPasskey(rp: String, user wanted: String, clientDataHash cdh: Data,
                                   uv: ASAuthorizationPublicKeyCredentialUserVerificationPreference, allow: [Data]) {
        purpose = .passkeySignIn(rp: rp)
        user = wanted
        link.site = rp
        show()
        let request = Ctap.getAssertion(rpId: rp, clientDataHash: cdh, allow: allow, uv: uv != .discouraged)
        let title = "Passkey sign-in for \(rp)"
        watch = link.$outcome.sink { [weak self] o in
            guard let self, case .ctap(let body)? = o else { return }
            do {
                let a = try Ctap.parseAssertion(body)
                guard self.passes(authData: a.authenticatorData, rp: rp, uvRequired: uv == .required, creating: false, title: title) else { return }
                let cred = ASPasskeyAssertionCredential(userHandle: a.userHandle, relyingParty: rp, signature: a.signature,
                                                        clientDataHash: cdh, authenticatorData: a.authenticatorData,
                                                        credentialID: a.credentialID)
                self.link.note("Handed to iOS")
                LastRequest.save(title, self.link.lines)
                self.closed = true
                self.extensionContext.completeAssertionRequest(using: cred)
            } catch {
                self.fail(error, creating: false)
                LastRequest.save(title, self.link.lines)
            }
        }
        retry = { [weak self] in self?.link.ctap(request) }
        link.ctap(request)
    }

    private func makePasskey(rp: String, user name: String, userHandle: Data, clientDataHash cdh: Data,
                             uv: ASAuthorizationPublicKeyCredentialUserVerificationPreference, algorithms: [Int]) {
        purpose = .passkeyCreate(rp: rp, user: name)
        user = name
        link.site = rp
        show()
        let request = Ctap.makeCredential(rpId: rp, clientDataHash: cdh, userHandle: userHandle, userName: name, algorithms: algorithms)
        let title = "Passkey creation for \(rp)"
        watch = link.$outcome.sink { [weak self] o in
            guard let self, case .ctap(let body)? = o else { return }
            do {
                let r = try Ctap.parseRegistration(body)
                self.link.note("KEY attestation \(r.fmt), handed to iOS as none; credential id \(r.credentialID.count) bytes")
                guard self.passes(authData: r.authenticatorData, rp: rp, uvRequired: uv == .required, creating: true, title: title) else { return }
                let cred = ASPasskeyRegistrationCredential(relyingParty: rp, clientDataHash: cdh,
                                                           credentialID: r.credentialID, attestationObject: r.attestationObject)
                self.link.note("Handed to iOS")
                LastRequest.save(title, self.link.lines)
                self.closed = true
                AccountList.record(.init(passkey: true, site: rp, user: name, credentialID: r.credentialID, userHandle: userHandle)) {
                    self.extensionContext.completeRegistrationRequest(using: cred)
                }
            } catch {
                self.fail(error, creating: true)
                LastRequest.save(title, self.link.lines)
            }
        }
        retry = { [weak self] in self?.link.ctap(request) }
        link.ctap(request)
    }

    // MARK: -

    /// Check the KEY's authenticator data before iOS sees it. On a problem the
    /// sheet stays open and says why instead of handing iOS something it refuses.
    private func passes(authData: Data, rp: String, uvRequired: Bool, creating: Bool, title: String) -> Bool {
        guard let c = Ctap.check(authData: authData, rpId: rp) else {
            link.showFailure("The KEY's reply was too short to use.")
            LastRequest.save(title, link.lines)
            return false
        }
        link.note("Checked: " + c.summary + (uvRequired ? ", UV required" : ""))
        let problems = c.problems(uvRequired: uvRequired, creating: creating)
        guard problems.isEmpty else {
            link.showFailure("Not handed to iOS: " + problems.joined(separator: "; ") + ".")
            LastRequest.save(title, link.lines)
            return false
        }
        return true
    }

    /// A reply came back but it's a refusal or unreadable: say so on the sheet.
    private func fail(_ error: Error, creating: Bool) {
        let why: String
        switch error {
        case Ctap.Failure.status(let s): why = Ctap.message(forStatus: s, creating: creating)
        default: why = "The KEY's reply couldn't be used (\(error))."
        }
        link.showFailure(why)
    }

    private func close() {
        guard !closed else { return }
        closed = true
        link.cancel()
        if configuring { extensionContext.completeExtensionConfigurationRequest(); return }
        LastRequest.save("Request closed on the sheet", link.lines)
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                          code: ASExtensionError.userCanceled.rawValue))
    }
}
