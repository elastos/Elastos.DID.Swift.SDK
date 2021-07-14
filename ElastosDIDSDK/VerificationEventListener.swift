/*
* Copyright (c) 2021 Elastos Foundation
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

import Foundation

open class VerificationEventListener: NSObject {

    /// Reset current listener to the initial state.
    /// After reset the listener, it should be safe to reuse.
    open func reset() {}
    
    open func done(context: NSObject, succeeded: Bool, message: String) {}
    
    func succeeded(context: NSObject, args: String...) {
        var message = ""
        args.forEach { msg in
            message.append(msg)
            message.append(" ")
        }
        done(context: context, succeeded: true, message: message)
    }
    
    func failed(context: NSObject, args: String...) {
        var message = ""
        args.forEach { msg in
            message.append(msg)
            message.append(" ")
        }
        done(context: context, succeeded: false, message: message)
    }
    
    /// Get the default VerificationEventListener implementation. The listener
    /// will gather all messages and return a stringify result.
    /// - Parameters:
    ///   - ident: ident string for each message
    ///   - succeededPrefix: prefix string for the succeeded messages
    ///   - failedPrefix: prefix string for the failed messages
    /// - Returns: the default VerificationEventListener instance
    public static func getDefault(_ ident: String, _ succeededPrefix: String, _ failedPrefix: String) -> VerificationEventListener {
        return DefaultVerificationEventListener(ident: ident, succeededPrefix: succeededPrefix, failedPrefix: failedPrefix)
    }

    /// Get the default VerificationEventListener implementation. The listener
    /// will gather all messages and return a stringify result.
    /// - Parameter ident: ident string for each message
    /// - Returns: the default VerificationEventListener instance
    public static func getDefault(_ ident: String) -> VerificationEventListener {
        return DefaultVerificationEventListener(ident: ident)
    }
    
    public func toString() -> String {
        return description
    }
}

public class DefaultVerificationEventListener: VerificationEventListener {
    private let EMPTY = ""
    
    private var ident: String
    private var succeededPrefix: String
    private var failedPrefix: String
    
    private var records: [Record] = [ ]
    
    public init(ident: String = "", succeededPrefix: String = "", failedPrefix: String = "") {
        self.ident = ident
        self.succeededPrefix = succeededPrefix
        self.failedPrefix = failedPrefix
    }
    
    public override func done(context: NSObject, succeeded: Bool, message: String) {
        records.append(Record(context, succeeded, message))
    }
    
    public override func reset() {
        records.removeAll()
    }
    
    public override var description: String {
        var str = ""
        records.forEach { record in
            str.append(ident)
            str.append(" ")
            str.append(record.succeeded ? succeededPrefix : failedPrefix)
            str.append(" ")
            str.append(record.message)
            str.append("\n")
        }
        return str
    }
    
    public override func toString() -> String {
        return description
    }
}

public class Record: NSObject {
    var context: NSObject
    var succeeded: Bool
    var message:String
    
    public init(_ context: NSObject, _ succeeded: Bool, _ message: String) {
        self.context = context
        self.succeeded = succeeded
        self.message = message
    }
}
