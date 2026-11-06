// CredentialProviderViewController.swift - the AutoFill extension (KEY drop 8z7).
//
// When the user picks Favilla in iOS's sign-in sheet, the extension sends the
// site to the KEY over Bluetooth and closes. The owner picks the login on the
// KEY and presses; the KEY types it into the page as the phone's Bluetooth
// keyboard. The extension never receives a password (ruled 6 Nov 2026), so it
// returns no credential: closing it hands the focus back to the login field.

import AuthenticationServices
import Combine
import SwiftUI

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let link = KeyLink()
    private var notice: String?
    private var configuring = false
    private var watch: AnyCancellable?
    private var closed = false

    override func viewDidLoad() {
        super.viewDidLoad()
        show()
    }

    private func show() {
        guard isViewLoaded else { return }   // viewDidLoad shows it
        children.forEach { $0.view.removeFromSuperview(); $0.removeFromParent() }
        let onClose = { [weak self] in self?.close() }
        let root: AnyView = configuring
            ? AnyView(ProbeView(link: link, title: "FAVILLA", onClose: onClose).preferredColorScheme(.dark))
            : AnyView(SignInView(link: link, notice: notice, onClose: onClose).preferredColorScheme(.dark))
        let host = UIHostingController(rootView: root)
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    // Passwords: the sheet's "Favilla" entry, for this site.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        start(site: serviceIdentifiers.first?.identifier ?? "")
    }

    // Passkeys (iOS 17): not from the KEY on iPhone yet.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        notice = "Passkeys from your KEY can't be used on iPhone yet. Use the password for this site, or sign in on a computer with the KEY plugged in."
        show()
    }

    // Settings > AutoFill & Passwords > Favilla: run the link check there.
    override func prepareInterfaceForExtensionConfiguration() {
        configuring = true
        show()
        link.probe()
    }

    private func start(site: String) {
        show()
        link.site = site
        // Once the KEY has the ask, give the user a moment to read the screen,
        // then close so the page's field has the focus when the KEY types.
        watch = link.$outcome.sink { [weak self] o in
            guard o == .sent else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { self?.close() }
        }
        link.signIn()
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
