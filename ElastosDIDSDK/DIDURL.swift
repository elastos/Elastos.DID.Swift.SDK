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

    private var _parameters: OrderedDictionary<String, String> = OrderedDictionary()
    private var _path: String?
    var _queryParameters: OrderedDictionary<String, String> = OrderedDictionary()
    private var _metadata: CredentialMetadata?
    var _queryString: String?
    var repr: String = ""

    override init() {
        super.init()
    }
    
    ///  Constructs the DIDURl with the given value.
    /// - Parameters:
    ///   - baseRef: base the owner of DIDURL
    ///   - url: url the DIDURl string
    /// - Throws: If error occurs, throw error.
    @objc
    public init(_ context: DID, _ url: String) throws {
        super.init()
        try checkArgument(!url.isEmpty, "Invalid url")
        let parser = DIDURLParser(self)
        try parser.parse(context, url)
    }
    
    /// Constructs a DIDURL object with the given DID context and a DIDURL object.
    /// - Parameters:
    ///   - context: context a DID context of the DIDURL object, if the url is a relative DIDURL
    ///   - url: url a DIDURL object
    public init(_ context: DID, _ url: DIDURL) {
        super.init()
        self.setDid(context)
        if (url.did != nil) {
            self.setDid(url.did!)
        }
        self._path = url.path
        self._parameters = url._parameters
        self._queryParameters = url._queryParameters
        self._queryString = url.queryString
        self._fragment = url.fragment
        self.repr = url.repr
        self._metadata = url._metadata
    }

    /// Constructs a DIDURL object with the given DID context and a DIDURL object.
    /// - Parameter url: url a DIDURL object
    public init(_ url: DIDURL) {
        super.init()
        if (url.did != nil) {
            self.setDid(url.did!)
        }
        self._path = url.path
        self._queryParameters = url._queryParameters
        self._queryString = url.queryString
        self._fragment = url.fragment
        self._parameters = url._parameters
        self.repr = url.repr
        self._metadata = url._metadata
    }
    
    /// Constructs a DIDURL object with the given DID context and a DIDURL object.
    /// - Parameter context: context a DID context of the DIDURL object, if the url is a relative DIDURL
    public init(_ context: DID) {
        super.init()
        self.setDid(context)
        self._queryParameters = OrderedDictionary()
    }

    /// Get DID URL from string.
    /// - Parameter url: A  string including id information. idstring support: 1. “did:elastos:xxxxxxx#xxxxx”
    /// - Throws: If error occurs, throw error.
    @objc
    public init(_ url: String) throws {
        super.init()
        let parser = DIDURLParser(self)
        try parser.parse(url)
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
        return _parameters[ofKey]
    }

    /// Check is contains parameter
    /// - Parameter forKey: The key string.
    /// - Returns: true if has value, or false.
    @objc
    public func containsParameter(forKey: String) -> Bool {
        return _parameters.keys.contains(forKey)
    }

    func appendParameter(_ value: String?, forKey: String) {
        self._parameters[forKey] = value
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
    public func queryParameters() -> [String: String] {
        var query: [String: String] = [: ]
        _queryParameters.forEach { k, v in
            query[k] = v
        }
        
        return query
    }
    
    public var queryString: String? {
        self._queryString = mapToString(_queryParameters, "&")

        return _queryString
    }
    
    func setQueryString(_ newValue: String) {
        self._queryString = newValue
    }

    /// Query DIDURL parameter by key.
    /// - Parameter ofKey: The key string .
    /// - Returns: if has value , return value string .
    @objc
    public func queryParameter(ofKey: String) -> String? {
        return _queryParameters[ofKey]
    }

    /// Check is contains query parameter .
    /// - Parameter forKey: The key string .
    /// - Returns: true if has value, or false.
    @objc
    public func containsQueryParameter(forKey: String) -> Bool {
        return _queryParameters.keys.contains(forKey)
    }

    /// Add key-value for parameters .
    /// - Parameters:
    ///   - value: The value string .
    ///   - forKey: The key string.
    @objc
    public func appendQueryParameter(_ value: String?, forKey: String) {
        self._queryParameters[forKey] = value
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

    /// Sets a query parameter with given value.
    /// - Parameters:
    ///   - name: a query parameter name
    ///   - value: the parameter value
    /// - Throws: the builder instance for method chaining
    public func setQueryParameter(_ name: String, _ value: String) throws {
        try checkArgument(!name.isEmpty, "Invalid parameter name")
        
        _queryParameters[name] = value
    }
    
    func deepClone(_ readonly: Bool) -> DIDURL {
        let result = DIDURL()
        result.setDid(self.did!)
        result.setPath(self.path!)
        result._queryParameters = (self._queryParameters.count == 0 && readonly) ? OrderedDictionary() : _queryParameters
        result.setQueryString(self.queryString!)
        result._fragment = self.fragment
        result.repr = self.repr

        return result
    }
}

extension DIDURL {
    
    func toString(_ base: DID) -> String {
        var builder: String = ""
        if did != nil && did != base {
            builder.append(did!.toString())
        }
        if !(path?.isEmpty ?? true) {
            builder.append(path!)
        }
        if (_queryParameters.count > 0) {
            builder.append("?")
            builder.append(queryString!)
        }
        if !(_fragment?.isEmpty ?? true) {
            builder.append("#")
            builder.append(fragment!)
        }
        
        return builder
    }

    func toString() -> String {
        var builder: String = ""

        builder.append(did?.toString() ?? "")
        if !(path?.isEmpty ?? true) {
            builder.append(path!)
        }
        if (queryString != nil && _queryParameters.count > 0) {
            builder.append("?")
            builder.append(queryString!)
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
        if repr == "" {
            repr = toString()
        }
        return repr
    }
    
    public func serialize() -> String {
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
    
    public func isQualified() -> Bool {
        return (did != nil && fragment != nil);
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

