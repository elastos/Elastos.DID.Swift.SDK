import Foundation

public class Features: NSObject {
    static var enabledJsonLdContext = false
    
    public class func enableJsonLdContext(_ enabled: Bool) {
        enabledJsonLdContext = enabled
    }
    
    public class func isEnabledJsonLdContext() -> Bool {
        return enabledJsonLdContext
    }
}
