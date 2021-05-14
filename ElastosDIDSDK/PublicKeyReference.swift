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
import ObjectMapper

public class PublicKeyReference: NSObject {
     private var _id: DIDURL?
     private var _key: PublicKey?
     
     init(_ id: DIDURL) {
         _id = id
     }
     
     init(_ key: PublicKey) {
         _key = key
     }
    
    init(_ id: DIDURL, _ key: PublicKey) {
        _id = id
        _key = key
    }
     
     public var isReference: Bool {
         return _id != nil
     }
     
     public var id: DIDURL? {
         return _id
     }
     
     public var publicKey: PublicKey? {
         return _key
     }
     
     public var isVirtual: Bool {
         return _key != nil
     }
     
     func update(_ key: PublicKey) throws {
         try checkArgument(key.getId() == id, "")
         self._id = key.getId()
         self._key = key
     }

     public func weaken() {
         if _key != nil {
             self._id = _key!.getId()
             self._key = nil
         }
     }
     
    public func compareTo(_ ref: PublicKeyReference) throws -> ComparisonResult {
        if self.publicKey != nil && ref.publicKey != nil {
            return try self.publicKey!.compareTo(ref.publicKey!)
        } else {
            try checkNotNull(self.id == nil || ref.id == nil, "id is null")
            return self.id!.compareTo(ref.id!)
        }
    }
 }
