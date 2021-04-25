
import Foundation

class EcdsaSigner: NSObject {

    class func sha256Digest(_ data: [Data]) -> Data {
        var cinputs: [CVarArg] = []
        var capacity: Int = 0
        data.forEach { data in
            let json = String(data: data, encoding: .utf8)
            if json != "" {
                let cjson = json!.toUnsafePointerInt8()!
                cinputs.append(cjson)
                cinputs.append(json!.lengthOfBytes(using: .utf8))
                capacity += json!.count * 3
            }
        }

        let c_inputs = getVaList(cinputs)
        let count = cinputs.count / 2
//        _capacity = capacity
        // digest
        let cdigest = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let size = sha256v_digest(cdigest, Int32(count), c_inputs)
        let cdigestPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cdigest, count: size)

        return Data(buffer: cdigestPointerToArry)
    }
}
