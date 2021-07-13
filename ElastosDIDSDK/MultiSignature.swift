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

/// MultiSignature is a digital signature scheme which allows a group of
/// users to sign a single document.
public class MultiSignature: NSObject {
    static let ONE_OF_ONE = try? MultiSignature(1, 1)

    private var _m: Int
    private var _n: Int
    
    /// Create a MultiSignature instance with given signature specification.
    ///
    /// The MultiSignature can be of the m-of-n type where any m private
    /// keys out of a possible n are required to sign/verify the signature.
    ///
    /// - Parameters:
    ///   - m: m required keys
    ///   - n: n possible keys
    public init(_ m: Int, _ n: Int) throws {
        _m = m
        _n = n
        super.init()
        try apply(m, n)
    }
    
    /// Copy constructor.
    /// - Parameter ms: the source MultiSignature object
    init(_ ms: MultiSignature) throws {
        _m = ms._m
        _n = ms._n
        super.init()
        try apply(ms._m, ms._n)
    }
    
    /// Create a MultiSignature instance with given signature specification.
    /// - Parameter mOfN: the string format m-of-n(m:n)
    public init(_ mOfN: String) throws {
        if mOfN.isEmpty {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Invalid multisig spec")
        }
        let mn: [Substring] = mOfN.split(separator: ":")
        guard mn.count == 2 else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Invalid multisig spec")
        }
        // note: test       !!!!
        _m = Int(mn[0])!
        _n = Int(mn[1])!
        super.init()
        try apply(_m, _n)
    }
    
    func apply(_ m: Int, _ n: Int) throws {
        try checkArgument(n > 0, "Invalid multisig spec: n should > 1");
        try checkArgument(m > 0 && m <= n,  "Invalid multisig spec: m should > 0 and <= n");
    }
    
    /// Get the m of requested signatures.
    public var m: Int {
        return _m
    }
    
    /// Get the n of possible signatures.
    public var n: Int {
        return _n
    }
    
    /// Return the string representation of this MultiSignature object.
    public override var description: String {
        return String("\(m):\(n)")
    }
}

/// Compares this MultiSignature to the specified object.
/// The result is true if and only if the argument is not nil and
/// is a MultiSignature object that represents the same schema.
///
/// @param obj the object to compare this MultiSignature against
/// @return true if the given object represents a MultiSignature
///            equivalent to this object, false otherwise
extension MultiSignature {
    public func equalsTo(_ other: MultiSignature) -> Bool {
        return m == other.m && n == other.n
    }

    public static func == (lhs: MultiSignature, rhs: MultiSignature) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: MultiSignature, rhs: MultiSignature) -> Bool {
        return !lhs.equalsTo(rhs)
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        if object is MultiSignature {
            return equalsTo(object as! MultiSignature)
        }
        else {
            return equalsTo(object as! MultiSignature)
        }
    }
}
