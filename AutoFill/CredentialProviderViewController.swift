// CredentialProviderViewController.swift - the AutoFill extension (probe stage).
//
// The make-or-break check: when iOS shows its sign-in sheet and the user picks
// Favilla, can this extension reach the KEY over Bluetooth? It runs the probe
// and shows the result. It returns no credential yet; Close cancels the request.

import AuthenticationServices
import SwiftUI

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let link = KeyLink()

    override func viewDidLoad() {
        super.viewDidLoad()
        let root = ProbeView(link: link, title: "FAVILLA", onClose: { [weak self] in self?.close() })
            .preferredColorScheme(.dark)
        let host = UIHostingController(rootView: root)
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    // Passwords: the sheet's "Favilla" entry, for this site.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        link.site = serviceIdentifiers.first?.identifier ?? ""
        link.probe()
    }

    // Passkeys (iOS 17): a sign-in with a passkey, for this relying party.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        link.site = requestParameters.relyingPartyIdentifier
        link.probe()
    }

    // Settings > AutoFill & Passwords > Favilla.
    override func prepareInterfaceForExtensionConfiguration() {
        link.probe()
    }

    private func close() {
        link.cancel()
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                          code: ASExtensionError.userCanceled.rawValue))
    }
}
