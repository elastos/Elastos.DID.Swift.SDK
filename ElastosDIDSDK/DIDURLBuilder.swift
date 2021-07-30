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

/// Builder class to create or modify a DIDURL.
public class DIDURLBuilder: NSObject {

    var url: DIDURL
    
    /// Create DIDURL builder object with given url as default pattern.
    /// - Parameter url: a DIDURL object
    public init(_ url: DIDURL) {
        self.url = url.deepClone(false)
    }
    
    /// Create DIDURL builder object with given did as base DID.
    /// - Parameter did: a DID object as the base DID
    public init(_ did: DID) {
        self.url = DIDURL(did).deepClone(false)
    }
    
    /// Set the base DID object of the DIDURL that to be build.
    /// - Parameter did: a DID object, could be null
    /// - Returns: the builder instance for method chaining
    public func setDid(_ did: DID) -> DIDURLBuilder {
        url.setDid(did)
        
        return self
    }
    
    /// Set the base DID object of the DIDURL that to be build.
    /// - Parameter did: a DID object, could be null
    /// - Returns: the builder instance for method chaining
    public func setDid(_ did: String) throws -> DIDURLBuilder {
        try url.setDid(DID.valueOf(did)!)
        
        return self
    }
    
    /// Set the path component of the DIDURL object.
    /// - Parameter path: a path string
    /// - Returns: the builder instance for method chaining
    public func setPath(_ path: String) throws -> DIDURLBuilder {
        if path.count > 0  {
            url.setPath(path)
        }
        else {
            url.setPath("")
        }
        
        return self
    }
    
    /// Append a query parameter with given value.
    /// - Parameter:
    ///     - name: a query parameter name
    ///     - value: value: the parameter value
    /// - Returns: the builder instance for method chaining
    public func appendQueryParameter(_ name: String, _ value: String) throws -> DIDURLBuilder {
        try checkArgument(!name.isEmpty, "Invalid parameter name")
        url._queryParameters[name] = value
        
        return self
    }
    
    /// Sets query parameters with given map object. All the previous
    /// parameters and values will be clear.
    /// - Parameter: a string/string map object for query parameters
    /// - Returns: the builder instance for method chaining
    public func setQueryParameters(_ params: [String: String]) throws -> DIDURLBuilder {
        url._queryParameters.removeAll(keepCapacity: 0)
        if (params.count > 0) {
            params.forEach { (k, v) in
                url._queryParameters[k] = v
            }
        }

        return self
    }
    
    /// Remove the specific parameter from the query parameters.
    /// - Parameter: name: the parameter name to be remove
    /// - Returns: the builder instance for method chaining
    public func removeQueryParameter(_ name: String) throws -> DIDURLBuilder {
        try checkArgument(!name.isEmpty, "Invalid parameter name")

        _ = url._queryParameters.removeValueForKey(key: name)
        return self
    }
    
    /// Remove all the existing parameters from the query parameters component.
    /// - Returns: the builder instance for method chaining
    public func clearQueryParameters() throws -> DIDURLBuilder {
        url._queryParameters.removeAll(keepCapacity: 0)
        
        return self
    }
    
    /// Set the fragment component.
    /// - Parameter fragment: a fragment string
    /// - Returns: the builder instance for method chaining
    public func setFragment(_ fragment: String) throws -> DIDURLBuilder {
        url.setFragment(fragment)
        
        return self
    }
    
    public func build() -> DIDURL {
        return url.deepClone(true)
    }
}
