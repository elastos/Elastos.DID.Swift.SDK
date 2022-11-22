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
import Sodium
import Clibsodium

public class DIDXChaCha20Poly1305Cipher: DIDCipher {
    
    public let ABytes = Int(crypto_aead_xchacha20poly1305_ietf_abytes())
    public var _key: [UInt8]

    init(_ key: [UInt8]) {
        _key = key
    }
    
    public func setOtherSideCurve25519PublicKey(_ key: [UInt8]) throws {
        throw DIDError.UncheckedError.UnsupportedOperationError.UnsupportedError("Not support yet.")
    }
    
    public func encrypt(_ data: [UInt8], _ nonce: [UInt8]) throws -> [UInt8] {
        
        if data.count < 0 {
            print("Invalid data")
        }
        
        if nonce.count < 0 {
            print("Invalid nonce")
        }
        
        var authenticatedCipherText = [UInt8](repeating: 0, count: data.count + ABytes)
        var authenticatedCipherTextLen: UInt64 = 0
        
        var exitCode: Int32 = -1
        exitCode = crypto_aead_xchacha20poly1305_ietf_encrypt (
            &authenticatedCipherText, &authenticatedCipherTextLen,
            data,
            UInt64(data.count),
            nil,
            0,
            nil,
            nonce,
            self._key
        )
        
        if exitCode != 0 {
            print("Failed to encrypt data.")
        }

        return authenticatedCipherText

    }
    
    public func decrypt(_ data: [UInt8], _ nonce: [UInt8]) throws -> [UInt8] {
        
        if data.count < 0 {
            print("Invalid data")
        }
        
        if nonce.count < 0 {
            print("Invalid nonce")
        }
                
        var message = [UInt8](repeating: 0, count: data.count - ABytes)
        var messageLen: UInt64 = 0
        
        var exitCode: Int32 = -1

        exitCode = crypto_aead_xchacha20poly1305_ietf_decrypt (
            &message,
            &messageLen,
            nil,
            data,
            UInt64(data.count),
            nil,
            0,
            nonce,
            self._key
        )
        
        if exitCode != 0 {
            print("Failed to decrypt data.")
        }

        return message
    }
    
    public func createEncryptionStream() throws -> EncryptionStream {
        return try DIDSSEncrypt(self._key)
    }
    
    public func createDecryptionStream(_ header: [UInt8]) throws -> DecryptionStream {
        return try DIDSSDecrypt(self._key, header)
    }
    
    public func getEd25519PublicKey() throws -> [UInt8] {
        print("Not support yet.")
        return [UInt8](repeating: 0, count: 0)

    }
    
    public func getCurve25519PublicKey() throws -> [UInt8] {
        print("Not support yet.")
        return [UInt8](repeating: 0, count: 0)
    }
}
