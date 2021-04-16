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
    private var _specification: String?
    private var _operation: IDChainRequestOperation?
    private var _previousTxid: String?
    private var _ticket: String?
    private var _transferTicket: TransferTicket?
    
    init(_ spec: String) {
        self._specification = spec
    }
    
    init(_ operation: IDChainRequestOperation, _ previousTxid: String) {
        self._operation = operation
        self._previousTxid = previousTxid
    }
    
    init(_ operation: IDChainRequestOperation, _ ticket: TransferTicket) {
        self._operation = operation
//        let json = ticket.toString(true)
        // TODO:
//        self.ticket =
        self._transferTicket = ticket
    }
   
    init(_ operation: IDChainRequestOperation) {
        self._operation = operation
        switch operation {
        case .CREATE, .UPDATE, .TRANSFER, .DEACTIVATE:
            _specification = IDChainRequest.DID_SPECIFICATION
            break
        case .DECLARE, .REVOKE:
            _specification = IDChainRequest.CREDENTIAL_SPECIFICATION
            break
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
        /// TODO:
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
        generator.writeEndObject()
    }
    
    class func parse(_ content: JsonNode) -> IDChainHeader {
        let specification = content.get(forKey: "specification")!.asString()
        let operation = content.get(forKey: "operation")!.asString()
//        let previousTxid = content.get(forKey: "previousTxid")?.asString()
//        let ticket = content.get(forKey: "ticket")
//        let transferTicket = content.get(forKey: "transferTicket")
        let op = IDChainRequestOperation.valueOf(operation!)
        
      return IDChainHeader(op)
    }
}
