

import Foundation

@objc
public protocol DIDTransactionAdapter {
  
    /// User need to implement ‘createIdTransaction’ function.
    /// An application-defined function that create id transaction to chain.
    /// - Parameters:
    ///   - payload: The content of id transaction to publish.
    ///   - memo: Memo string.
    func createIdTransaction(_ payload: String,
                             _ memo: String?) throws
}
