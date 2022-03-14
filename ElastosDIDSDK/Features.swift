import Foundation

/// The global features for the DID SDK.
public class Features: NSObject {
    static var enabledJsonLdContext = false

    /// Enable or disable the JSON-LD feature.
    /// - Parameter enabled: true to enable the JSON-LD feature; false to disable
    public class func enableJsonLdContext(_ enabled: Bool) {
        enabledJsonLdContext = enabled
    }

    /// Check if the JSON-LD feature is enabled or not.
    /// - Returns: true if the JSON-LD feature is enabled, false otherwise
    public class func isEnabledJsonLdContext() -> Bool {
        return enabledJsonLdContext
    }
}
