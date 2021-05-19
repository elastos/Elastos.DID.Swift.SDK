/*
* Copyright (c) 2020 Elastos Foundation
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
import ObjectMapper

private func mapToString(_ dict: OrderedDictionary<String, String>?, _ sep: String) -> String? {
    guard let _ = dict else {
        return nil
    }

    var first  = true
    var result = ""

    for (key, value) in dict! {
        result.append(!first ? sep : "")
        result.append(key)
        if value != "" {
            result.append("=")
        }
        result.append(value)

        if  first {
            first = false
        }
    }
    return result
}

/// DID URL defines by the did-url rule, refers to a URL that begins with a DID followed by one or more additional components.
/// A DID URL always identifies the resource to be located. DIDURL includes DID and Url fragment by user defined.
@objc(DIDURL)
public class DIDURL: NSObject {
    private static let TAG = "DIDURL"

    private var _did: DID?
    private var _fragment: String?

    private var _parameters: OrderedDictionary<String, String>?
    private var _path: String?
    private var _queryParameters: OrderedDictionary<String, String>?
    private var _metadata: CredentialMetadata?

    ///  Constructs the DIDURl with the given value.
    /// - Parameters:
    ///   - baseRef: base the owner of DIDURL
    ///   - url: url the DIDURl string
    /// - Throws: If error occurs, throw error.
    @objc
    public init(_ baseRef: DID, _ url: String) throws {
        super.init()
        try checkArgument(!url.isEmpty, "Invalid url")
        var fragment = url
        if url.hasPrefix("did:") {
            do {
                try ParserHelper.parse(url, false, DIDURL.Listener(self))
            } catch {
                Log.e(DIDURL.TAG, "Parsing didurl error: malformed didurl string \(url)")
                throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDURLError("malformed DIDURL \(url)")
            }

            guard did == baseRef else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Mismatched arguments")
            }
            return
        }

        if !url.hasPrefix("#") {
            fragment = "#" + fragment
        }
        let starIndex = fragment.index(fragment.startIndex, offsetBy: 1)
        let endIndex  = fragment.index(starIndex, offsetBy: fragment.count - 2)
        fragment  = String(fragment[starIndex...endIndex])
        self._did = baseRef
        self._fragment = fragment
    }

    /// Get DID URL from string.
    /// - Parameter url: A  string including id information. idstring support: 1. “did:elastos:xxxxxxx#xxxxx”
    /// - Throws: If error occurs, throw error.
    @objc
    public init(_ url: String) throws {
        super.init()
        try checkArgument(!url.isEmpty, "Invalid url")
        do {
            try ParserHelper.parse(url, false, DIDURL.Listener(self))
        } catch {
            Log.e(DIDURL.TAG, "Parsing didurl error: malformed didurl string \(url)")
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDURLError("malformed DIDURL \(url)")
        }
    }
    
    public init(_ baseRef: DID, _ url: DIDURL) throws {
        _did = url._did == nil ? baseRef : url.did
        _parameters = url._parameters
        _path = url._path
        _queryParameters = url._queryParameters
        _fragment = url._fragment
        _metadata = url._metadata
    }

    public class func valueOf(_ baseRef: DID, _ url: String) throws -> DIDURL? {
        return url.isEmpty ? nil : try DIDURL(baseRef, url)
    }
    
    public class func valueOf(_ baseRef: String, _ url: String) throws -> DIDURL? {
        return url.isEmpty ? nil : try DIDURL(DID.valueOf(baseRef)!, url)
    }
    
    public class func valueOf(_ url: String) throws -> DIDURL {
        return try DIDURL(url)
    }

    // A valid didurl guaranteed containing valid did.
    @objc
    public var did: DID? {
        return _did
    }

    /// Set did
    /// - Parameter newValue: The new did
    @objc
    public func setDid(_ newValue: DID) {
        self._did = newValue
    }

    // Regards to DIDs v1.0 specs:
    // "DID URL: A DID plus an optional DID path, optional ? character followed
    //  by a DID query, and optional # character followed by a DID fragment."
    @objc
    public var fragment: String? {
        return _fragment
    }

    func setFragment(_ newValue: String) {
        self._fragment = newValue
    }

    /// Parameters for generating DIDURL .
    /// - Returns: DIDURL string .
    @objc
    public func parameters() -> String? {
        return mapToString(_parameters, ";")
    }

    /// Get value in the DIDURL parameter by the key .
    /// - Parameter ofKey: The key string.
    /// - Returns: If no has, return value string.
    @objc
    public func parameter(ofKey: String) -> String? {
        return _parameters?[ofKey]
    }

    /// Check is contains parameter
    /// - Parameter forKey: The key string.
    /// - Returns: true if has value, or false.
    @objc
    public func containsParameter(forKey: String) -> Bool {
        return _parameters?.keys.contains(forKey) ?? false
    }

    func appendParameter(_ value: String?, forKey: String) {
        if  self._parameters == nil {
            self._parameters = OrderedDictionary()
        }
        self._parameters![forKey] = value
    }

    /// Get DIDURL path.
    @objc
    public var path: String? {
        return _path
    }

    func setPath(_ newValue: String) {
        self._path = newValue
    }

    /// Query DIDURL parameters
    /// - Returns: DIDURL parameters string .
    @objc
    public func queryParameters() -> String? {
        return mapToString(_queryParameters, "&")
    }

    /// Query DIDURL parameter by key.
    /// - Parameter ofKey: The key string .
    /// - Returns: if has value , return value string .
    @objc
    public func queryParameter(ofKey: String) -> String? {
        return _queryParameters?[ofKey]
    }

    /// Check is contains query parameter .
    /// - Parameter forKey: The key string .
    /// - Returns: true if has value, or false.
    @objc
    public func containsQueryParameter(forKey: String) -> Bool {
        return _queryParameters?.keys.contains(forKey) ?? false
    }

    /// Add key-value for parameters .
    /// - Parameters:
    ///   - value: The value string .
    ///   - forKey: The key string.
    @objc
    public func appendQueryParameter(_ value: String?, forKey: String) {
        if  self._queryParameters == nil {
            self._queryParameters = OrderedDictionary()
        }
        self._queryParameters![forKey] = value
    }

    func setMetadata(_ metadata: CredentialMetadata) {
        self._metadata = metadata
    }

    /// Get CredentialMetaData from Credential.
    /// - Returns: Return the handle to CredentialMetaData
    @objc
    public func getMetadata() -> CredentialMetadata {
        if  self._metadata == nil {
            self._metadata = CredentialMetadata()
        }
        return self._metadata!
    }
}

extension DIDURL {
    
    func toString(_ base: DID) -> String {
        var builder: String = ""
        if did != nil && did != base {
            builder.append(did!.toString())
        }
        if (parameters() != nil) {
            builder.append(";")
            builder.append(parameters()!)
        }
        if !(path?.isEmpty ?? true) {
            builder.append(path!)
        }
        if (queryParameters() != nil) {
            builder.append("?")
            builder.append(queryParameters()!)
        }
        if !(_fragment?.isEmpty ?? true) {
            builder.append("#")
            builder.append(fragment!)
        }
        
        return builder
    }

    func toString() -> String {
        var builder: String = ""

        builder.append(did!.toString())
        if (parameters() != nil) {
            builder.append(";")
            builder.append(parameters()!)
        }
        if !(path?.isEmpty ?? true) {
            builder.append(path!)
        }
        if (queryParameters() != nil) {
            builder.append("?")
            builder.append(queryParameters()!)
        }

        if !(_fragment?.isEmpty ?? true) {
            builder.append("#")
            builder.append(fragment!)
        }
        return builder
    }

    /// Get id string from DID URL.
    @objc
    public override var description: String {
        return toString()
    }
}

extension DIDURL {
    public func equalsTo(_ other: DIDURL) -> Bool {
        return toString() == other.toString()
    }

    public func equalsTo(_ other: String) -> Bool {
        return toString() == other
    }

    public static func == (lhs: DIDURL, rhs: DIDURL) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: DIDURL, rhs: DIDURL) -> Bool {
        return !lhs.equalsTo(rhs)
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        if object is DIDURL {
            return equalsTo(object as! DIDURL)
        }
        else {
            return equalsTo(object as! String)
        }
    }
    
    @objc
    public func compareTo(_ id: DIDURL) -> ComparisonResult {
        return self.toString().compare(id.toString())
    }
}

// DIDURL used as hash key.
extension DIDURL {
//    public func hash(into hasher: inout Hasher) {
//        hasher.combine(self.toString())
//    }
    public override var hash: Int {
        return self.toString().hash
    }
}

// Parse Listener
extension DIDURL {
    class Listener: DIDURLBaseListener {
        private var name: String?
        private var value: String?
        private var didURL: DIDURL?

        init(_ didURL: DIDURL) {
            self.didURL = didURL
            super.init()
        }

        override func enterDid(_ ctx: DIDURLParser.DidContext) {
            self.didURL?.setDid(DID())
        }

        override func exitMethod(_ ctx: DIDURLParser.MethodContext) {
            let method = ctx.getText()
            if  method != Constants.METHOD {
                print("Unknown method: \(method)")
            }
            self.didURL?.did!.setMethod(Constants.METHOD)
        }

        override func exitMethodSpecificString(
                            _ ctx: DIDURLParser.MethodSpecificStringContext) {
            self.didURL?.did!.setMethodSpecificId(ctx.getText())
        }

        override func enterParams(_ ctx: DIDURLParser.ParamsContext) {
            self.didURL?._parameters = OrderedDictionary()
        }

        override func exitParamMethod(_ ctx: DIDURLParser.ParamMethodContext) {
            let method = ctx.getText()
            if  method != Constants.METHOD {
                Log.e(DIDURL.TAG, "Unknown parameter method: \(method)")
            }
            self.didURL?.did!.setMethod(method)
        }

        override func exitParamQName(_ ctx: DIDURLParser.ParamQNameContext) {
            self.name = ctx.getText()
        }

        override func exitParamValue(_ ctx: DIDURLParser.ParamValueContext) {
            self.value = ctx.getText()
        }

        override func exitParam(_ ctx: DIDURLParser.ParamContext) {
            let value = self.value ?? ""
            self.didURL?.appendParameter(value, forKey: self.name!)
            self.name = nil
            self.value = nil
        }

        override func exitPath(_ ctx: DIDURLParser.PathContext) {
            self.didURL?.setPath("/" + ctx.getText())
        }

        override func enterQuery(_ ctx: DIDURLParser.QueryContext) {
            self.didURL?._queryParameters = OrderedDictionary()
        }

        override func exitQueryParamName(_ ctx: DIDURLParser.QueryParamNameContext) {
            self.name = ctx.getText()
        }

        override func exitQueryParamValue(_ ctx: DIDURLParser.QueryParamValueContext) {
            self.value = ctx.getText()
        }

        override func exitQueryParam(_ ctx: DIDURLParser.QueryParamContext) {
            let value = self.value ?? ""
            self.didURL?.appendQueryParameter(value, forKey: self.name!)
            self.name = nil
            self.value = nil
        }

        override func exitFrag(_ ctx: DIDURLParser.FragContext) {
            self.didURL?.setFragment(ctx.getText())
        }
    }
}
