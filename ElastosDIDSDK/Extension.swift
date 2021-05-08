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
        guard full else {
            throw DIDError.UncheckedError.IllegalArgumentError.IllegalUsageError(mesg)
        }
    }
    
    func checkNotNull(_ full: Bool, _ mesg: String) throws {
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
    
    func toDictionary() -> [String : Any] {
        
        var result = [String : Any]()
        guard !self.isEmpty else { return result }
        
        guard let dataSelf = self.data(using: .utf8) else {
            return result
        }
        
        if let dic = try? JSONSerialization.jsonObject(with: dataSelf,
                           options: []) as? [String : Any] {
            result = dic ?? [: ]
        }
        return result
    }
    
    func forReading() throws -> Data {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: self) {
            let readhandle = FileHandle.init(forReadingAtPath: self)
            let data: Data = readhandle!.readDataToEndOfFile()
            return data
        }
        else {
            throw DIDError.unknownFailure("path not Exists.")
        }
    }
    
    func forReading() throws -> String {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: self) {
            let readhandle = FileHandle.init(forReadingAtPath: self)
            let data = readhandle!.readDataToEndOfFile()
            return  String(data: data, encoding: .utf8) ?? ""
        }
        else {
            throw DIDError.unknownFailure("path not Exists.")
        }
    }
    
    func readTextFromPath() throws -> String {
        guard try self.exists() else {
            return ""
        }
        return try String(contentsOfFile: self, encoding: String.Encoding.utf8)
    }
}

extension Dictionary {
   public func toJsonString() -> String? {
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

extension Array {
   public func toJsonString() -> String? {
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

extension Data {
    
    func dataToDictionary() throws -> [String: Any] {
        let json = try JSONSerialization.jsonObject(with: self, options: .mutableContainers)
        let dic = json as? [String: Any]
        guard let _ = dic else {
            throw DIDError.unknownFailure("Change json to [String: Any] failed.")
        }
        return dic!
    }
    
    func dataToDictionary() throws -> [String: String] {
        
        let json = try JSONSerialization.jsonObject(with: self, options: .mutableContainers)
        let dic = json as? [String: String]
        
        guard let _ = dic else {
            throw DIDError.unknownFailure("Change json to [String: Any] failed.")
        }
        return dic!
    }
}

extension Array where Element == UInt8 {
    var hexString: String {
        return self.compactMap { String(format: "%02x", $0).lowercased() }
        .joined(separator: "")
    }
}
