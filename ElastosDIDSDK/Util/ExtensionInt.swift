
import Foundation

extension Int {
    
    static prefix  func ++(num:inout Int) -> Int  {
        num += 1
        return num
    }
    
    static postfix  func ++(num:inout Int) -> Int  {
        let temp = num
        num += 1
        return temp
    }
    
    static prefix  func --(num:inout Int) -> Int  {
        num -= 1
        return num
    }
    
    static postfix  func --(num:inout Int) -> Int  {
        let temp = num
        num -= 1
        return temp
    }
    
    static func randomCustom(min: Int, max: Int) -> Int {
            //  [min, max)  [0, 100)
            //        var x = arc4random() % UInt32(max);
            //        return Int(x)
            // [min, max）
            let y = arc4random() % UInt32(max) + UInt32(min)
            print(Int(y))
            return Int(y)
    }
    
    static func decTohex(number:Int) -> String {
         return String(format: "%0X", number)
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

extension Dictionary {
    mutating func merge(dict: [Key: Value]){
        for (k, v) in dict {
            updateValue(v, forKey: k)
        }
    }
    
    var queryString: String {
        var output: String = ""
        for (key,value) in self {
            output +=  "\(key)=\(value)&"
        }
        output = String(output.dropLast())
        return output
    }
}

extension Character {
    var asciiValue: UInt32? {
        return String(self).unicodeScalars.filter{$0.isASCII}.first?.value
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
}
