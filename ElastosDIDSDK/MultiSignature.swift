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

public class MultiSignature: NSObject {
    private var _m: Int
    private var _n: Int
    
    public init(_ m: Int, _ n: Int) throws {
        _m = m
        _n = n
        super.init()
        try apply(m, n)
    }
    
    private init(_ ms: MultiSignature) throws {
        _m = ms._m
        _n = ms._n
        super.init()
        try apply(ms._m, ms._n)
    }
    
    public init(_ mOfN: String) throws {
        if mOfN.isEmpty {
            throw DIDError.IllegalArgumentError("Invalid multisig spec")
        }
        let mn: [Substring] = mOfN.split(separator: ":")
        guard mn.count == 2 else {
            throw DIDError.IllegalArgumentError("Invalid multisig spec")
        }
        // note: test       !!!!
        _m = Int(mn[0])!
        _n = Int(mn[1])!
        super.init()
        try apply(_m, _n)
    }
    
    func apply(_ m: Int, _ n: Int) throws {
        if (m <= 0 || n <= 1 || m > n) {
            throw DIDError.IllegalArgumentError("Invalid multisig spec")
        }
    }
    
    public var m: Int {
        return _m
    }
    
    public var n: Int {
        return _n
    }
    
    public override var description: String {
        return String("\(m)\(n)")
    }
}
