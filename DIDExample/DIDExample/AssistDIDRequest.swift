
import UIKit
import ElastosDIDSDK

class AssistDIDRequest {
    //    "did"
    var did: DID!
    //    "memo"
    var memo: String?
    //    "requestFrom"
    var agent: String!
    //    "didRequest"
    var request: DIDRequest!
    
    init(_ payload: String, _ memo: String?) {
        do {
            self.request = try DIDRequest.deserialize(payload)
            self.did = request.did!
            self.memo = memo
            self.agent = "DID command line utils"
        } catch {
            print("AssistDIDRequest init Error: \(error)")
        }
    }
    
    func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField("did", did.description)
        if memo == nil || memo == "" {
            generator.writeStringField("memo", "")
        }
        else {
            generator.writeStringField("memo", memo!)
        }
        generator.writeStringField("requestFrom", agent)
        generator.writeFieldName("didRequest")
        request.serialize(generator)
        generator.writeEndObject()
    }
    
    func description() -> String {
        let jsonGenerator = JsonGenerator()
        serialize(jsonGenerator)
        return jsonGenerator.toString()
    }
}
