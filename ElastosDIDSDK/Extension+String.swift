
import Foundation

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
            let dirPath: String = PathExtracter(self).dirname()
            let fileM = FileManager.default
            let re = fileM.fileExists(atPath: dirPath)
            if !re {
                try fileM.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            FileManager.default.createFile(atPath: self, contents: nil, attributes: nil)
        }
    }
}

