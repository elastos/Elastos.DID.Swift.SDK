/**
 * Copyright IBM Corporation 2018
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Foundation

// MARK: Claims
public class Claims {
    /**
     The "iss" (issuer) claim identifies the principal that issued the
     JWT.  The processing of this claim is generally application specific.
     The "iss" value is a case-sensitive.
     */
    public static let iss: String = "iss"

    /**
     The "sub" (subject) claim identifies the principal that is the
     subject of the JWT.  The claims in a JWT are normally statements
     about the subject.  The subject value MUST either be scoped to be
     locally unique in the context of the issuer or be globally unique.
     The processing of this claim is generally application specific.  The
     "sub" value is case-sensitive.
     */
    public static let sub: String = "sub"

    /**
     The "aud" (audience) claim identifies the recipients that the JWT is
     intended for.  Each principal intended to process the JWT MUST
     identify itself with a value in the audience claim.  If the principal
     processing the claim does not identify itself with a value in the
     "aud" claim when this claim is present, then the JWT MUST be
     rejected. The interpretation of audience values is generally application specific.
     The "aud" value is case-sensitive.
     */
    public static let aud: String = "aud"

    /**
     The "exp" (expiration time) claim identifies the expiration time on
     or after which the JWT MUST NOT be accepted for processing.  The
     processing of the "exp" claim requires that the current date/time
     MUST be before the expiration date/time listed in the "exp" claim.
     Implementers MAY provide for some small leeway, usually no more than
     a few minutes, to account for clock skew.
     */
    public static let exp: String = "exp"

    /**
     The "nbf" (not before) claim identifies the time before which the JWT
     MUST NOT be accepted for processing.  The processing of the "nbf"
     claim requires that the current date/time MUST be after or equal to
     the not-before date/time listed in the "nbf" claim.  Implementers MAY
     provide for some small leeway, usually no more than a few minutes, to
     account for clock skew.
     */
    public static let nbf: String = "nbf"

    /**
     The "iat" (issued at) claim identifies the time at which the JWT was
     issued.  This claim can be used to determine the age of the JWT.
     */
    public static let iat: String = "iat"

    /**
     The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     The identifier value MUST be assigned in a manner that ensures that
     there is a negligible probability that the same value will be
     accidentally assigned to a different data object; if the application
     uses multiple issuers, collisions MUST be prevented among values
     produced by different issuers as well.  The "jti" claim can be used
     to prevent the JWT from being replayed.  The "jti" value is case-
     sensitive
     */
    public static let jti: String = "jti"

    var claims: [String: Any] = [: ]

    public init() { }

    public func getIssuer() -> String? {
        return claims[Claims.iss] as? String
    }

    public func setIssuer(issuer: String) -> Claims {
        claims[Claims.iss] = issuer
        return self
    }

    public func setSubject(subject: String) -> Claims {
        claims[Claims.sub] = subject
        return self
    }

    public func getSubject() -> String? {
        return claims[Claims.sub] as? String
    }

    public func getAudience() -> String? {
        return claims[Claims.aud] as? String
    }

    public func setAudience(audience: String) -> Claims {
        claims[Claims.aud] = audience
        return self
    }

    public func getExpiration() -> Date? {
        return DateHelper.getDateFromTimeStamp(claims[Claims.exp] as? Int)
    }

    public func setExpiration(expiration: Date) -> Claims {
        claims[Claims.exp] = DateHelper.getTimeStamp(expiration)
        return self
    }

    public func getNotBefore() -> Date? {
        return DateHelper.getDateFromTimeStamp(claims[Claims.nbf] as? Int)
    }

    public func setNotBefore(notBefore: Date) -> Claims {
        claims[Claims.nbf] = DateHelper.getTimeStamp(notBefore)
        return self
    }

    public func getIssuedAt() -> Date? {
        
        return DateHelper.getDateFromTimeStamp(claims[Claims.iat] as? Int)
    }

    public func setIssuedAt(issuedAt: Date) -> Claims {
        claims[Claims.iat] = DateHelper.getTimeStamp(issuedAt)
        return self
    }

    public func getId() -> String? {
        return claims[Claims.jti] as? String
    }

    public func setId(id: String) -> Claims {
        claims[Claims.jti] = id
        return self
    }

    public func size() -> Int {
        return claims.count
    }

    public func isEmpty() -> Bool {
        return claims.isEmpty
    }

    public func containsKey(key: String) -> Bool {
        return claims[key] != nil
    }

    public func containsValue(value: Any) -> Bool {
        for v in claims.values {
            if v as AnyObject === value as AnyObject {
                return true
            }
        }
        return false
    }

    public func get(key: String) -> Any {
        return claims[key] as Any
    }

    public func getAsJson(key: String) throws -> String {
        let v = claims[key]
        if !(v is String) && v != nil {
            let data = try JSONSerialization.data(withJSONObject: v as Any, options: [])
            return (String(data: data, encoding: .utf8)!)
        }
        throw DIDError.illegalArgument("TODO")
    }

    public func put(key: String, value: Any) {
        claims[key] = value
    }

    public func putWithJson(key: String, value: String) throws {
        let dic = try JSONSerialization.jsonObject(with: value.data(using: .utf8)!, options: [])
        claims[key] = dic
    }

    public func remove(key: String) -> Any? {
        let value = claims[key]
        claims.removeValue(forKey: key)

        return value
    }

    public func putAll(dic: [String: Any]) {
        claims.merge(dict: dic)
    }

    public func putAllWithJson(json: String) throws {
        let dic = try JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: []) as? [String : Any]
        guard dic != nil else {
            throw DIDError.illegalArgument("TODO")
        }
        putAll(dic: dic!)
    }

    public func clear() {
        claims.removeAll()
    }

    public func values() -> [Any] {
        var values = [Any]()
        claims.forEach { k, v in
            values.append(v)
        }
        return values
    }

    public func setValue(key: String, value: Any) -> Claims {
        claims[key] = value
        return self
    }
}

public extension Claims {
    
    func encode() throws -> String {
        let data = try JSONSerialization.data(withJSONObject: claims, options: [])
//        print(String(data: data, encoding: .utf8))
        return JWTEncoder.base64urlEncodedString(data: data)
    }

   class func decode(_ data: Data) throws -> Claims {
        let dic = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        let cla = Claims()
        if dic != nil {
            cla.claims = dic!
        }
        return cla
    }
}
