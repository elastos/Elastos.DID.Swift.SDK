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

@objc(IDTransactionInfo)
public class IDTransactionInfo: NSObject {

    private let TXID = "txid"
    private let TIMESTAMP = "timestamp"
    private let OPERATION = "operation"

    private var _transactionId: String
    private var _timestamp: Date
    private var _request: IDChainRequest

    /// Constructs the IDChainTransaction with the given value.
    /// - Parameters:
    ///   - transactionId: The transaction id string.
    ///   - timestamp: The time stamp
    ///   - request: The IDChainRequest content.
    @objc
    public init(_ transactionId: String, _ timestamp: Date, _ request: IDChainRequest) {
        self._transactionId = transactionId
        self._timestamp = timestamp
        self._request = request
    }

    /// Get transaction id.
    /// - Returns: The handle of transaction id.
    @objc
    public func getTransactionId() -> String {
        return self.transactionId
    }

    /// Get time stamp.
    /// - Returns: The handle time stamp.
    @objc
    public func getTimestamp() -> Date {
        return self.timestamp
    }

    @objc
    public var transactionId: String {
        return self._transactionId
    }

    @objc
    public var timestamp: Date {
        return self._timestamp
    }

    /// The IDChainRequest object.
    @objc
    public var request: IDChainRequest {
        return self._request
    }

    func sanitize() throws {
        guard !transactionId.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Missing txid")
        }
        do {
           try request.sanitize()
        } catch {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Invalid request")
        }
    }
    
//    /// Get IDChainTransaction from json content.
//    /// - Parameter node: the JsonNode content
//    /// - Throws: DIDTransaction error.
//    /// - Returns:The IDChainTransaction object.
//    @objc
//    public class func fromJson(_ node: JsonNode) throws -> IDTransactionInfo {
//        let error = { (des: String) -> DIDError in
//            return DIDError.didResolveError(des)
//        }
//
//        let serializer = JsonSerializer(node)
//        var options: JsonSerializer.Options
//
//        options = JsonSerializer.Options()
//                                .withHint("transaction id")
//                                .withError(error)
//        let transactionId = try serializer.getString(Constants.TXID, options)
//
//        options = JsonSerializer.Options()
//                                .withHint("transaction timestamp")
//                                .withError(error)
//        let timestamp = try serializer.getDate(Constants.TIMESTAMP, options)
//
//        let subNode = node.get(forKey: Constants.OPERATION)
//        guard let _ = subNode else {
//            throw DIDError.didResolveError("missing ID operation")
//        }
//
//        let request = try IDChainRequest.fromJson(subNode!)
//        return IDTransactionInfo(transactionId, timestamp, request)
//    }
//
//    /// Get json string with input content.
//    /// - Parameter generator: the JsonGenerator handle.
//    @objc
//    public func toJson(_ generator: JsonGenerator) {
//        generator.writeStartObject()
//        generator.writeStringField(Constants.TXID, self.transactionId)
//        generator.writeStringField(Constants.TIMESTAMP, self.timestamp.description)
//
//        generator.writeFieldName(Constants.OPERATION)
//        self._request.toJson(generator, false)
//        generator.writeEndObject()
//    }
    
    public func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(Constants.TXID, self.transactionId)
        generator.writeStringField(Constants.TIMESTAMP, self.timestamp.description)
        
        generator.writeFieldName(Constants.OPERATION)
        self._request.serialize(generator, false)
        generator.writeEndObject()
    }
    
    public func serialize() -> String {
        let generator = JsonGenerator()
        serialize(generator)
        
        return generator.toString().NFC()
    }
}
