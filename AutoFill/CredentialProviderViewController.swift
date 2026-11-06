// CredentialProviderViewController.swift - the AutoFill extension.
//
// Passwords (KEY drop 8z7): the extension sends the site to the KEY and closes.
// The owner picks the login on the KEY and presses; the KEY types it into the
// page as the phone's Bluetooth keyboard. The extension never receives a
// password (ruled 6 Nov 2026), so it returns no credential.
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

    // MARK: - Passwords: the sheet's "Favilla" entry, for this site.

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        purpose = .password
        show()
        link.site = serviceIdentifiers.first?.identifier ?? ""
        // Once the KEY has the ask, give the user a moment to read the screen,
        // then close so the page's field has the focus when the KEY types.
        watch = link.$outcome.sink { [weak self] o in
            guard o == .sent else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { self?.close() }
        }
        retry = { [weak self] in self?.link.signIn() }
        link.signIn()
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
                let cred = ASPasskeyAssertionCredential(userHandle: a.userHandle, relyingParty: rp, signature: a.signature,
                                                        clientDataHash: cdh, authenticatorData: a.authenticatorData,
                                                        credentialID: a.credentialID)
                self.closed = true
                self.extensionContext.completeAssertionRequest(using: cred)
            } catch {
                self.fail(error, creating: false)
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
                let cred = ASPasskeyRegistrationCredential(relyingParty: rp, clientDataHash: cdh,
                                                           credentialID: r.credentialID, attestationObject: r.attestationObject)
                self.closed = true
                self.extensionContext.completeRegistrationRequest(using: cred)
            } catch {
                self.fail(error, creating: true)
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
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                          code: ASExtensionError.userCanceled.rawValue))
    }
}
