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

@objc(IDChainRequestOperation)
/// The IDChain Request Operations.
public enum IDChainRequestOperation: Int, CustomStringConvertible {
    case CREATE = 0 // Create a new DID
    case UPDATE = 1 // Update an exist DID
    case TRANSFER // Deactivate a DID
    case DEACTIVATE // Transfer the DID' ownership
    case DECLARE // Declare a credential
    case REVOKE // Revoke a credential

    func toString() -> String {
        let desc: String
        switch self.rawValue {
        case 0:
            desc = "create"
        case 1:
            desc = "update"
        case 2:
            desc = "transfer"
        case 3:
            desc = "deactivate"
        case 4:
            desc = "declare"
        default:
            desc = "revoke"
        }
        return desc;
    }

    public static func valueOf(_ str: String) -> IDChainRequestOperation {
        let operation: IDChainRequestOperation

        switch str.uppercased() {
        case "CREATE":
            operation = .CREATE

        case "UPDATE":
            operation = .UPDATE

        case "TRANSFER":
            operation = .TRANSFER
            
        case "DEACTIVATE":
            operation = .DEACTIVATE
            
        case "DECLARE":
            operation = .DECLARE

        default:
            operation = .REVOKE
        }
        return operation
    }

    /// Get IDChainRequestOperation string.
    public var description: String {
        return toString()
    }
}
