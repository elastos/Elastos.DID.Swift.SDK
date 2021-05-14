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
            enumerator.removeObject(sub)
        }
        
        if enumerator.count == 0 {
            try fileManager.removeItem(atPath: self)
        }
    }

}

