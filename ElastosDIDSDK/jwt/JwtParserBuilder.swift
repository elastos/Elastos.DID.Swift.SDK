/*
* Copyright (c) 2019 Elastos Foundation
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

@objc(JwtParserBuilder)
public class JwtParserBuilder: NSObject {

    var getPublicKey : ((_ id: String?) throws -> Data)?
    var getPrivateKey : ((_ id: String?, _ storePassword: String) throws -> Data)?
    var claimsJwt : String?
    var key: String?
    private var allwedClockSkewSeconds: Int = 0


    /// Constructs the empty JwtParserBuilder.
    @objc
    public override init() { }

    /// Constructs the JwtParserBuilder with the specified key.
    /// - Parameter withKey: The verfiy key.
    @objc
    public init(_ withKey: String) {
        key = withKey
    }

    /// Parse jwt token.
    /// - Parameter claimsJwt: Jwt token.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: The handle of JWT.
    @objc
    public func parseClaimsJwt(_ claimsJwt: String) throws -> JWT {
        let publicKey = try self.getPublicKey!(key)
        let jwtVerifier = JWTVerifier.es256(publicKey: publicKey)
        return try JWT(jwtString: claimsJwt, verifier: jwtVerifier, allwedClockSkewSeconds: allwedClockSkewSeconds)
    }
    
    public func setAllwedClockSkewSeconds(_ seconds: Int) -> JwtParserBuilder {
        allwedClockSkewSeconds = seconds
        
        return self
    }

    /// Create JwtParser
    /// - Returns: JwtParser instance.
    @objc
    public func build() throws -> JwtParser {
        guard let _ =  getPublicKey else {
            return JwtParser(nil, allwedClockSkewSeconds)
        }
        return JwtParser(try self.getPublicKey!(key), allwedClockSkewSeconds)
    }
}

@objc(JwtParser)
public class JwtParser: NSObject {

    var jwt: JWT?
    var publickey: Data?
    var allwedClockSkewSeconds: Int = 0
    init(_ key: Data?, _ allwedClockSkewSeconds: Int) {
        self.publickey = key
        self.allwedClockSkewSeconds = allwedClockSkewSeconds
    }
    /// Parse jwt token.
    /// - Parameter claimsJwt: Jwt token.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: The handle of JWT.
    @objc
    public func parseClaimsJwt(_ claimsJwt: String) throws -> JWT {
        guard let _ = publickey else {
            return try JWT(jwtString: claimsJwt, allwedClockSkewSeconds: allwedClockSkewSeconds)
        }

        let jwtVerifier = JWTVerifier.es256(publicKey: publickey!)
        return try JWT(jwtString: claimsJwt, verifier: jwtVerifier, allwedClockSkewSeconds: allwedClockSkewSeconds)
    }

    /// Get jwt header.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: Jwt Header.
    @objc
    public func getHeader() throws -> Header {
        return jwt!.header;
    }

    /// Get jwt claims.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: Jwt Claims.
    @objc
    public func getBody() throws -> Claims {
        return jwt!.claims;
    }
}
