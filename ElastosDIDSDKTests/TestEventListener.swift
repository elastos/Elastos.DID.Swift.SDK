
import Foundation
import ElastosDIDSDK

class TestEventListener: VerificationEventListener {

    override init() { }
    
    override func done(context: NSObject, succeeded: Bool, message: String) {
        print("Debug:===============> context = \(context), \nDebug:===============> succeeded = \(succeeded), \nDebug:===============> message = \(message)")
    }
}
