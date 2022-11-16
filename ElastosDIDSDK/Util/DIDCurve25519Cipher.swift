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

public class DIDCurve25519Cipher: DIDCipher {
    
    private var encryptKey: [UInt8]!
    private var sharedKeys: KeyExchange.SessionKeyPair!
    private var keyPair: DIDCurve25519KeyPair
    private var isServer: Bool

    init(_ key: DIDCurve25519KeyPair, _ isServer: Bool) {
        
        self.keyPair = key
        self.isServer = isServer
    }
    
    private func checkEncryptionKeys() throws {
        if ((self.encryptKey == nil) || (self.sharedKeys == nil)) {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Please set an other side public key first.")
        }
    }
    
    public func setOtherSideCurve25519PublicKey(_ key: [UInt8]) {
        
        let sodium = Sodium()
        self.encryptKey = sodium.box.beforenm(recipientPublicKey: key, senderSecretKey: self.keyPair.privateKey)
        
        self.sharedKeys = self.isServer ? sodium.keyExchange.sessionKeyPair(publicKey: self.keyPair.publicKey, secretKey: self.keyPair.privateKey, otherPublicKey: key, side: .SERVER) : sodium.keyExchange.sessionKeyPair(publicKey: self.keyPair.publicKey, secretKey: self.keyPair.privateKey, otherPublicKey: key, side: .CLIENT)

    }

    public func encrypt(_ data: [UInt8], _ nonce: [UInt8]) throws -> [UInt8] {
        
        if data.count == 0 {
            print("Invalid data")
        }
        
        if nonce.count == 0 {
            print("Invalid nonce")
        }
                
        var authenticatedCipherText = [UInt8](repeating: 0, count: data.count + Int(crypto_box_macbytes()))

        var result: Int32 = -1
        result = crypto_box_easy_afternm (
            &authenticatedCipherText,
            data,
            UInt64(data.count),
            nonce,
            self.encryptKey!
        )
        
        if result != 0 {
            print("Failed to decrypt data.")
        }
        
        return authenticatedCipherText
    }
    
    public func decrypt(_ data: [UInt8], _ nonce: [UInt8]) throws -> [UInt8] {
        
        if data.count == 0 {
            print("Invalid data")
        }
        
        if nonce.count == 0 {
            print("Invalid nonce")
        }
        
        var message = [UInt8](repeating: 0, count: data.count - Int(crypto_box_macbytes()))
        var result: Int32 = -1
        result = crypto_box_open_easy_afternm(&message,
                                              data,
                                              UInt64(data.count),
                                              nonce,
                                              self.encryptKey!)
        
        if result != 0 {
            print("Failed to decrypt data.")
        }
        return message

    }
    
    public func createEncryptionStream() throws -> EncryptionStream {
        try self.checkEncryptionKeys()
        return try DIDSSEncrypt(self.sharedKeys!.tx)
    }
    
    public func createDecryptionStream(_ header: [UInt8]) throws -> DecryptionStream {
        try self.checkEncryptionKeys()
        return try DIDSSDecrypt(self.sharedKeys!.rx, header)
    }
    
    public func getEd25519PublicKey() throws -> [UInt8] {
        return self.keyPair.ed25519Pk
    }
    
    public func getCurve25519PublicKey() throws -> [UInt8] {
        return self.keyPair.publicKey
    }
}
