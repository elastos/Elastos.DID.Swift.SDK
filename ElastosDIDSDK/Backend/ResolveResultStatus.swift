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

@objc(ResolveResultStatus)
public enum ResolveResultStatus: Int, CustomStringConvertible {
    case STATUS_VALID = 0
    case STATUS_EXPIRED = 1
    case STATUS_DEACTIVATED = 2
    case STATUS_NOT_FOUND = 3

    func toString() -> String {
        let desc: String
        switch self.rawValue {
        case 0:
            desc = "valid"
        case 1:
            desc = "expired"
        case 2:
            desc = "deactivated"
        case 3:
            desc = "not_found"
        default:
            desc = "not_found"
        }
        return desc
    }

    /// ResolveResultStatus string.
    public var description: String {
        return toString()
    }
}
