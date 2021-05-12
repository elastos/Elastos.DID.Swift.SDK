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

/// Header class for the ID transaction request.
public class IDChainHeader: NSObject {
    private var _specification: String? // must have value
    private var _operation: IDChainRequestOperation? // must have value
    private var _previousTxid: String?
    private var _ticket: String?
    private var _transferTicket: TransferTicket?
    
    init(_ spec: String) {
        self._specification = spec
    }
    
    init(_ operation: IDChainRequestOperation, _ previousTxid: String) {
        self._operation = operation
        self._previousTxid = previousTxid
        super.init()
        initOperation()
    }
    
    init(_ operation: IDChainRequestOperation, _ ticket: TransferTicket) {
        self._operation = operation
        self._transferTicket = ticket
        super.init()
        parseTicket(ticket)
        initOperation()
    }
    
    private func parseTicket(_ ticket: TransferTicket) {
        
        let json = ticket.serialize()
        let capacity = json.count * 3

        let cInput = json.toUnsafePointerUInt8()
        let cPayload = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
        let re = b64_url_encode(cPayload, cInput, json.lengthOfBytes(using: .utf8))
        cPayload[re] = 0
        self._ticket = String(cString: cPayload)
    }
   
    init(_ operation: IDChainRequestOperation) {
        self._operation = operation
        super.init()
        initOperation()
    }
    
    func initOperation() {
        switch _operation {
        case .CREATE, .UPDATE, .TRANSFER, .DEACTIVATE:
            _specification = IDChainRequest.DID_SPECIFICATION
            break
        case .DECLARE, .REVOKE:
            _specification = IDChainRequest.CREDENTIAL_SPECIFICATION
            break
        case .none: break
        }
    }
    
    /// Get the specification of this request.
    public var specification: String? {
        return _specification
    }
    
    /// Get the operation.
    public var operation: IDChainRequestOperation? {
        
        return _operation
    }
    
    /// Get the previous transaction id header.
    public var previousTxid: String? {
        return _previousTxid
    }
    
    /// Get the transfer ticket header.
    public var ticket: String? {
        return _ticket
    }
    
    func setTicket(_ ticket: String) {
        self._ticket = ticket
    }
    
    public var transferTicket: TransferTicket? {
        
        return _transferTicket
    }
    
    func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        if let _ = specification {
            generator.writeStringField("specification", specification!)
        }
        if let _ = operation {
            generator.writeStringField("operation", operation!.description)
        }
        if let _ = previousTxid {
            generator.writeStringField("previousTxid", previousTxid!)
        }

        if let _ = ticket  {
            generator.writeFieldName("ticket")
            generator.writeString(ticket!)
        }
        generator.writeEndObject()
    }
    
    class func parse(_ content: JsonNode) -> IDChainHeader {
        let operation = content.get(forKey: "operation")!.asString()
        let previousTxid = content.get(forKey: "previousTxid")?.asString()
        let ticket = content.get(forKey: "ticket")
        var transferTicket: TransferTicket?
        if let _ = ticket {
            transferTicket = try! TransferTicket.deserialize(ticket!.toString())
        }
        
        let op = IDChainRequestOperation.valueOf(operation!)
        if let _ = previousTxid {
            return IDChainHeader(op, previousTxid!)
        }
        if let _ = transferTicket {
            return IDChainHeader(op, transferTicket!)
        }
        
      return IDChainHeader(op)
    }
}
