

import Foundation

// MARK: base64
extension String {
    
    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
    
    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }
    
    func slip() -> [String] {
        if let index = self.lastIndex(of: ".") {
            
            let endIndex = self.index(index, offsetBy: 1)

            let firstWord = self[..<index]
            let lastWord = self[endIndex...]
            
            return [String(firstWord), String(lastWord)]
        }
        
        return ["", ""]
    }

}

// MARK: base64url
public extension Data {
    init?(base64urlEncoded input: String) {
        var base64 = input
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64 = base64.appending("=")
        }
        self.init(base64Encoded: base64)
    }
    
    func base64urlEncodedString() -> String {
        var result = self.base64EncodedString()
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }
}

extension Array {
    
    func filter(_ source: [String], _ path: String, _ start: String, _ end: String) -> [String] {
        var result: [String] = []
        source.forEach { sub in
            let f = sub.components(separatedBy: "/").last
            if f != nil {
                if f!.hasPrefix(start) && f!.hasSuffix(end) {
                    result.append(sub)
                }
            }
        }

        return result
    }
}
