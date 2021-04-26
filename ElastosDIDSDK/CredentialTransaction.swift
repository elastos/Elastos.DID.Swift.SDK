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

public class CredentialTransaction: IDTransactionInfo {
    var _request: CredentialRequest
    
    init(_ txid: String, _ timestamp: Date, _ request: CredentialRequest) {
        self._request = request
        super.init(txid, timestamp, request)
    }
    
    public override var request: CredentialRequest {
        return _request
    }
    
    public var id: DIDURL? {
        return request.id
    }
    
    public override func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(Constants.TXID, self.transactionId)
        generator.writeStringField(Constants.TIMESTAMP, DateFormatter.convertToUTCStringFromDate(self.timestamp))
        
        generator.writeFieldName(Constants.OPERATION)
        request.serialize(generator)
        generator.writeEndObject()
    }
    
    public override func serialize() -> String {
        let generator = JsonGenerator()
        serialize(generator)
        
        return generator.toString()
    }
    
    public class func deserialize(_ json: [String: Any]) throws -> CredentialTransaction {
        let txid = json[Constants.TXID] as! String
        let timestamp = json[Constants.TXID] as! String
        let op = json[Constants.OPERATION]
        let request = try CredentialRequest.deserialize(JsonNode(op as Any))
        return CredentialTransaction(txid, DateFormatter.convertToUTCDateFromString(timestamp)!, request as! CredentialRequest)
    }
}

