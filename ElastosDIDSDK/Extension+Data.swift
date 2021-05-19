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

extension Data {
    
    func dataToDictionary() throws -> [String: Any] {
        let json = try JSONSerialization.jsonObject(with: self, options: .mutableContainers)
        let dic = json as? [String: Any]
        guard let _ = dic else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DataParsingError("Change json to [String: Any] failed.")
        }
        return dic!
    }
    
    func dataToDictionary() throws -> [String: String] {
        
        let json = try JSONSerialization.jsonObject(with: self, options: .mutableContainers)
        let dic = json as? [String: String]
        
        guard let _ = dic else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DataParsingError("Change json to [String: Any] failed.")
        }
        return dic!
    }
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    func toPointer() -> UnsafePointer<UInt8>? {
      let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
      let stream = OutputStream(toBuffer: buffer, capacity: count)

      stream.open()
      withUnsafeBytes({ (p: UnsafePointer<UInt8>) -> Void in
        stream.write(p, maxLength: count)
      })
      stream.close()

      return UnsafePointer<UInt8>(buffer)
    }
}
