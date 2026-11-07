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
            : AnyView(SignInView(link: link, purpose: purpose, user: user, notice: notice, onRetry: onRetry, onClose: onClose).preferredColorScheme(.dark))
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
            fillPassword(site: site, user: id.user, isApp: isApp)
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

    // Settings > AutoFill & Passwords > Favilla: the link check (and pairing).
    override func prepareInterfaceForExtensionConfiguration() {
        configuring = true
        show()
        link.probe()
    }

    // MARK: - Passwords

    private func fillPassword(site: String, user wanted: String, isApp: Bool = false) {
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
                LastRequest.save("Password for \(host)", self.link.lines)
                let cred = ASPasswordCredential(user: login.user, password: login.password)
                self.closed = true
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
