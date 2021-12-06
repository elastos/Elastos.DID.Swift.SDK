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

extension String {
    
    /*
     * example: /foo/bar/example.txt
     * dirNamePart() -> "/foo/bar/"
     */
    func dirname() -> String {
        let index = self.range(of: "/", options: .backwards)?.lowerBound
        let str = index.map(self.prefix(upTo:)) ?? ""
        return "\(str)/"
    }

    /*
     * example: /foo/bar/example.txt
     * baseNamePart() -> "exmaple.txt"
     */
    func basename() -> String {
        let arr = self.components(separatedBy: "/")
        let str = arr.last ?? ""
        return String(str)
    }
    
    public func files() throws -> [String] {
        let fileManager = FileManager.default
        var enumerator = try fileManager.contentsOfDirectory(atPath: self)
        
        //        let fileManager = FileManager.default
        //        var subPath: [String] = []
        //        let enumerator = try fileManager.contentsOfDirectory(at: URL(string: path)!, includingPropertiesForKeys: nil, options: FileManager.DirectoryEnumerationOptions.skipsHiddenFiles)
        //        for element: URL in enumerator {
        //      subPath.append(element.lastPathComponent)
        //        }
        enumerator = enumerator.filter{ value -> Bool in
            !value.isEqual(".DS_Store")
        }
        return enumerator
    }

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
    
    func toStringDictionary() -> [String : String] {
        
        var result = [String : String]()
        guard !self.isEmpty else { return result }
        
        guard let dataSelf = self.data(using: .utf8) else {
            return result
        }
        
        if let dic = try? JSONSerialization.jsonObject(with: dataSelf,
                           options: []) as? [String : String] {
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
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("path not Exists.")
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
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("path not Exists.")
        }
    }
    
    func readTextFromPath() throws -> String {
        guard try self.exists() else {
            return ""
        }
        return try String(contentsOfFile: self, encoding: String.Encoding.utf8)
    }
    
    func readIndexFromPath() throws -> Int {
        let handle = FileHandle(forReadingAtPath: self)
        defer {
            handle!.closeFile()
        }
        let data = handle!.readDataToEndOfFile()
        return data.withUnsafeBytes { (pointer: UnsafePointer<Int32>) -> Int in
            return Int(pointer.pointee)
        }
    }
    
    func create(forWrite: Bool) throws {
        if !FileManager.default.fileExists(atPath: self) && forWrite {
            let dirPath: String = self.dirname()
            let fileM = FileManager.default
            let re = fileM.fileExists(atPath: dirPath)
            if !re {
                try fileM.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            FileManager.default.createFile(atPath: self, contents: nil, attributes: nil)
        }
    }
    
    func isDirectory() -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        _ = fileManager.fileExists(atPath: self, isDirectory:&isDir)
        return isDir.boolValue
    }
    
    func createDir(_ create: Bool) throws {
        let fileManager = FileManager.default
        if create {
            var isDirectory = ObjCBool.init(false)
            let fileExists = FileManager.default.fileExists(atPath: self, isDirectory: &isDirectory)
            if !fileExists {
                try fileManager.createDirectory(atPath: self, withIntermediateDirectories: true, attributes: nil)
            }
        }
    }
    
    func writeTextToPath(_ text: String) throws {
//        let writePath = try getFile(false, self)
        let fileManager = FileManager.default
        // Delete before writing
        _ = try self.deleteFile()
        fileManager.createFile(atPath: self, contents:nil, attributes:nil)
        let handle = FileHandle(forWritingAtPath: self)
        handle?.write(text.data(using: String.Encoding.utf8)!)
    }

    func dirExists() throws -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        let re = fileManager.fileExists(atPath: self, isDirectory:&isDir)
        return re && isDir.boolValue
    }
    
    func fileExists() throws -> Bool {
        let fileManager = FileManager.default
        return fileManager.fileExists(atPath: self)
    }
    
    func fileExistsWithContent() throws -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        fileManager.fileExists(atPath: self, isDirectory:&isDir)
        let readhandle = FileHandle.init(forReadingAtPath: self)
        let data = (readhandle?.readDataToEndOfFile()) ?? Data()
        let str = String(data: data, encoding: .utf8) ?? ""
        return str.count > 0 ? true : false
    }
    
    func deleteFile() throws -> Bool {
        let fileManager = FileManager.default
        var isDir = ObjCBool.init(false)
        let fileExists = fileManager.fileExists(atPath: self, isDirectory: &isDir)
        // If path is a folder, traverse the subfiles under the folder and delete them
        let re: Bool = false
        guard fileExists else {
            return re
        }
        try fileManager.removeItem(atPath: self)
        return true
    }
    
    func deleteDir() throws {
        let fileManager = FileManager.default
        var enumerator = try fileManager.contentsOfDirectory(atPath: self)
        for sub in enumerator {
            let p = self + "/" + sub
            if p.isDirectory() {
                try p.deleteDir()
            }
            else {
                try fileManager.removeItem(atPath: p)
            }
//            enumerator.removeObject(sub)

        }
        
//        if enumerator.count == 0 {
            try fileManager.removeItem(atPath: self)
//        }
    }
}

extension String {
    var asciiArray: [UInt32] {
        return unicodeScalars.filter{$0.isASCII}.map{$0.value}
    }
    
    func toUnsafePointerUInt8() -> UnsafePointer<UInt8>? {
        guard let data = self.data(using: .utf8) else {
            return nil
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        let stream = OutputStream(toBuffer: buffer, capacity: data.count)
        stream.open()
        let value = data.withUnsafeBytes {
            $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
        }
        guard let val = value else {
            return nil
        }
        stream.write(val, maxLength: data.count)
        stream.close()
        
        return UnsafePointer<UInt8>(buffer)
    }
    
    func toUnsafePointerInt8() -> UnsafePointer<Int8>? {
        let str: NSString = self as NSString
        let strUnsafe = str.utf8String
        return strUnsafe
    }
    
    func toUnsafeMutablePointerInt8() -> UnsafeMutablePointer<Int8>? {
        return strdup(self)
    }
    
    func charAt(_ index: Int) -> String {
        return String(prefix(index + 1).suffix(1))
    }
    
    subscript (bounds: CountableClosedRange<Int>) -> String {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return String(self[start...end])
    }

    subscript (bounds: CountableRange<Int>) -> String {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return String(self[start..<end])
    }
    
    func regionMatches(_ toffset: Int, _ other: String, _ ooffset: Int, _ count: Int) -> Bool {
        if self.count < other.count {
            return false
        }
        let strA = self[toffset..<(toffset + count)]
        let strB = other[ooffset..<(ooffset + count)]
        return strA == strB
//        let sub = String(self[toffset...ooffset])
//        return sub == other
    }
}

extension Character {
    var asciiValue: UInt32? {
        return String(self).unicodeScalars.filter{$0.isASCII}.first?.value
    }
}

extension String{
    static func changeToInt(num: String) -> Int {
        let str = num.uppercased()
        var sum = 0
        for i in str.utf8 {
            sum = sum * 16 + Int(i) - 48 // 0-9 从48开始
            if i >= 65 {                 // A-Z 从65开始，但有初始值10，所以应该是减去55
                sum -= 7
            }
        }
        return sum
    }
}

extension String {
    func normalizedCanonicallyComposed() -> String {
        let mutable = NSMutableString(string: self) as CFMutableString
        CFStringNormalize(mutable, .KD) // OR .C
        return mutable as String
    }
}
