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

extension NSObject {
    static func checkArgument(_ full: Bool, _ mesg: String) throws {
        guard !full else {
            throw DIDError.UncheckedError.IllegalArgumentError.IllegalUsageError(mesg)
        }
    }
    
    func checkArgument(_ full: Bool, _ mesg: String) throws {
        guard !full else {
            throw DIDError.UncheckedError.IllegalArgumentError.IllegalUsageError(mesg)
        }
    }
}

extension FileSystemStorage {
    func checkArgument(_ full: Bool, _ mesg: String) throws {
        guard !full else {
            throw DIDError.UncheckedError.IllegalArgumentError.IllegalUsageError(mesg)
        }
    }
}

extension String {
    func stringValueToDic(_ str: String) -> [String : Any]?{
        let data = str.data(using: String.Encoding.utf8)
        if let dict = try? JSONSerialization.jsonObject(with: data!,
                        options: .mutableContainers) as? [String : Any] {
            return dict
        }

        return nil
    }
}

extension Dictionary {
    func toJsonString() -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: self,
                                                     options: []) else {
            return nil
        }
        guard let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        return str
     }
}