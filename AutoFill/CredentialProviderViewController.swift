// CredentialProviderViewController.swift - the AutoFill extension.
//
// Passwords (KEY drop 9c): the extension asks the KEY for the site's login
// (FILL on 8F1A0003, answer on 8F1A0004); the owner picks it on the KEY and
// presses ENTER; the extension hands it to iOS as an ASPasswordCredential and
// keeps nothing.
//
// Passkeys (KEY drop 9a, favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md):
// sign-in sends CTAP2 getAssertion and hands the KEY's signature to iOS;
// creation sends makeCredential and hands iOS the attestation object. One
// generic "Favilla" entry, no account names listed (ruled 5 Nov 2026).

import AuthenticationServices
import Combine
import SwiftUI

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let link = KeyLink()
    private var purpose: SheetPurpose = .password
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
            ? AnyView(ProbeView(link: link, title: "FAVILLA", onClose: onClose).preferredColorScheme(.dark))
            : AnyView(SignInView(link: link, purpose: purpose, notice: notice, onRetry: onRetry, onClose: onClose).preferredColorScheme(.dark))
        let host = UIHostingController(rootView: root)
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    // MARK: - Passwords: the sheet's "Favilla" entry, for this site (KEY 9c).

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        purpose = .password
        let site = serviceIdentifiers.first?.identifier ?? ""
        link.site = site
        show()
        watch = link.$outcome.sink { [weak self] o in
            guard let self, case .answer(let body)? = o else { return }
            do {
                let login = try Ctap.parseFill(body)
                self.link.note("Login from the KEY (username \(login.user.isEmpty ? "empty" : "\(login.user.count) characters")); handing it to iOS")
                LastRequest.save("Password for \(site)", self.link.lines)
                self.closed = true
                self.extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: login.user, password: login.password))
            } catch Ctap.FillFailure.status(let st) {
                self.link.showFailure(Ctap.message(forFillStatus: st))
                LastRequest.save("Password for \(site)", self.link.lines)
            } catch {
                self.link.showFailure("The KEY's answer couldn't be read.")
                LastRequest.save("Password for \(site)", self.link.lines)
            }
            self.link.clearAnswer()   // the password is not kept past here
        }
        retry = { [weak self] in self?.link.fill() }
        link.fill()
    }

    // MARK: - Passkeys: sign in (no account picked: the generic Favilla entry).

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        let rp = requestParameters.relyingPartyIdentifier
        let cdh = requestParameters.clientDataHash
        let uv = requestParameters.userVerificationPreference != .discouraged
        let allow = requestParameters.allowedCredentials
        purpose = .passkeySignIn(rp: rp)
        link.site = rp
        show()
        let request = Ctap.getAssertion(rpId: rp, clientDataHash: cdh, allow: allow, uv: uv)
        watch = link.$outcome.sink { [weak self] o in
            guard let self, case .ctap(let body)? = o else { return }
            do {
                let a = try Ctap.parseAssertion(body)
                guard self.passes(authData: a.authenticatorData, rp: rp, uvRequired: requestParameters.userVerificationPreference == .required,
                                  creating: false, title: "Passkey sign-in for \(rp)") else { return }
                let cred = ASPasskeyAssertionCredential(userHandle: a.userHandle, relyingParty: rp, signature: a.signature,
                                                        clientDataHash: cdh, authenticatorData: a.authenticatorData,
                                                        credentialID: a.credentialID)
                self.closed = true
                self.extensionContext.completeAssertionRequest(using: cred) { ok in
                    self.link.note(ok ? "iOS says the request had expired" : "Handed to iOS")
                    LastRequest.save("Passkey sign-in for \(rp)", self.link.lines)
                }
            } catch {
                self.fail(error, creating: false)
                LastRequest.save("Passkey sign-in for \(rp)", self.link.lines)
            }
        }
        retry = { [weak self] in self?.link.ctap(request) }
        link.ctap(request)
    }

    // A passkey identity iOS picked from its list: Favilla registers none, so
    // this needs the sheet.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                          code: ASExtensionError.userInteractionRequired.rawValue))
    }

    // MARK: - Passkeys: make one on the KEY.

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let req = registrationRequest as? ASPasskeyCredentialRequest,
              let id = req.credentialIdentity as? ASPasskeyCredentialIdentity else {
            notice = "iOS didn't send a passkey request Favilla can read."
            show()
            return
        }
        let rp = id.relyingPartyIdentifier
        let cdh = req.clientDataHash
        purpose = .passkeyCreate(rp: rp, user: id.userName)
        link.site = rp
        show()
        let algs = req.supportedAlgorithms.map { $0.rawValue }
        let request = Ctap.makeCredential(rpId: rp, clientDataHash: cdh, userHandle: id.userHandle,
                                          userName: id.userName, algorithms: algs)
        watch = link.$outcome.sink { [weak self] o in
            guard let self, case .ctap(let body)? = o else { return }
            do {
                let r = try Ctap.parseRegistration(body)
                self.link.note("KEY attestation \(r.fmt), handed to iOS as none; credential id \(r.credentialID.count) bytes, attestation object \(r.attestationObject.count) bytes")
                guard self.passes(authData: r.authenticatorData, rp: rp, uvRequired: req.userVerificationPreference == .required,
                                  creating: true, title: "Passkey creation for \(rp)") else { return }
                let cred = ASPasskeyRegistrationCredential(relyingParty: rp, clientDataHash: cdh,
                                                           credentialID: r.credentialID, attestationObject: r.attestationObject)
                self.closed = true
                self.extensionContext.completeRegistrationRequest(using: cred) { ok in
                    self.link.note(ok ? "iOS says the request had expired" : "Handed to iOS")
                    LastRequest.save("Passkey creation for \(rp)", self.link.lines)
                }
            } catch {
                self.fail(error, creating: true)
                LastRequest.save("Passkey creation for \(rp)", self.link.lines)
            }
        }
        retry = { [weak self] in self?.link.ctap(request) }
        link.ctap(request)
    }

    // MARK: - Settings > AutoFill & Passwords > Favilla: the link check.

    override func prepareInterfaceForExtensionConfiguration() {
        configuring = true
        show()
        link.probe()
    }

    // MARK: -

    /// Check the KEY's authenticator data before iOS sees it. Logs what it found
    /// (and saves it, since the sheet closes on success); on a problem the sheet
    /// stays open and says why instead of handing iOS something it will refuse.
    private func passes(authData: Data, rp: String, uvRequired: Bool, creating: Bool, title: String) -> Bool {
        guard let c = Ctap.check(authData: authData, rpId: rp) else {
            link.showFailure("The KEY's reply was too short to use.")
            LastRequest.save(title, link.lines)
            return false
        }
        link.note("Checked: " + c.summary + (uvRequired ? ", UV required" : ""))
        let problems = c.problems(uvRequired: uvRequired, creating: creating)
        LastRequest.save(title, link.lines)
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
        if !configuring { LastRequest.save("Request closed on the sheet", link.lines) }
        if configuring { extensionContext.completeExtensionConfigurationRequest(); return }
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                          code: ASExtensionError.userCanceled.rawValue))
    }
}
