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

// Class to encrypt & decrypt message or stream data.
public protocol DIDCipher {
    
    // Set the other side public key for curve25519
    func setOtherSideCurve25519PublicKey(_ key: [UInt8]) throws

    /// Encrypt the message with small size.
    /// - Parameters:
    ///   - data: the data to be encrypted.
    ///   - nonce: the nonce for encryption.
    /// - Throws: if no error occurs, throw error.
    func encrypt(_ data: [UInt8], _ nonce: [UInt8]) throws -> [UInt8]

    /// Decrypt the message with small size.
    /// - Parameters:
    ///   - data: the data to be decrypted.
    ///   - nonce: the nonce for decryption, same as the nonce on encrypt().
    /// - Throws: if no error occurs, throw error.
    func decrypt(_ data: [UInt8], _ nonce: [UInt8]) throws -> [UInt8]

    // Get a encrypt stream for large size.
    func createEncryptionStream() throws -> EncryptionStream

    /// Get a decrypt stream for large size.
    /// - Parameters:
    ///   - header: the header from EncryptionStream.
    /// - Throws: if no error occurs, throw error.
    func createDecryptionStream(_ header: [UInt8]) throws -> DecryptionStream

    // Get the public key for ed25519
    func getEd25519PublicKey() throws -> [UInt8]
    
    // Get the public key for curve25519
    func getCurve25519PublicKey() throws -> [UInt8]
}

// Stream class to encrypt data.
public class EncryptionStream {
    public func header() throws -> [UInt8] {
        throw DIDError.UncheckedError.UnsupportedOperationError.UnsupportedError("Not implemented.")
    }

    public func push(_ clearText: [UInt8]) throws -> [UInt8] {
        return try self.pushAny(clearText, true)
    }

    public func pushLast(_ clearText: [UInt8]) throws -> [UInt8] {
        return try self.pushAny(clearText, true)
    }

    public func pushAny(_ clearText: [UInt8], _ isFinal: Bool) throws -> [UInt8] {
        throw DIDError.UncheckedError.UnsupportedOperationError.UnsupportedError("Not implemented.")
    }
}

//  Stream class to decrypt data.
public class DecryptionStream {
    public static func getHeaderLen() -> Int {
        return SecretStream.XChaCha20Poly1305.HeaderBytes
    }

    public static func getEncryptExtraSize() -> Int {
        return SecretStream.XChaCha20Poly1305.ABytes
    }

    public func pull(_ cipherText: [UInt8]) throws -> [UInt8] {
        throw DIDError.UncheckedError.UnsupportedOperationError.UnsupportedError("Not implemented.")
    }

    public func isComplete() throws -> Bool {
        throw DIDError.UncheckedError.UnsupportedOperationError.UnsupportedError("Not implemented.")
    }
}

public class DIDSSEncrypt: EncryptionStream {
    
    private var state: crypto_secretstream_xchacha20poly1305_state
    private var _header: [UInt8]

    init(_ key: [UInt8]) throws {

        let KeyBytes = Int(crypto_secretstream_xchacha20poly1305_keybytes())
        let HeaderBytes = Int(crypto_secretstream_xchacha20poly1305_headerbytes())
        
        if key.count != KeyBytes {
            print("")
        }

        self.state = crypto_secretstream_xchacha20poly1305_state()

        self._header = [UInt8](repeating: 0, count: HeaderBytes)
        var result: Int32 = -1
        result = crypto_secretstream_xchacha20poly1305_init_push(
            &self.state,
            &self._header,
            key
        )
        
        if result != 0 {
            print("Failed to init encryption.")
        }
    }

    public override func header() -> [UInt8] {
        return self._header
    }

    public override func pushAny(_ clearText: [UInt8], _ isFinal: Bool) throws -> [UInt8] {

        let tag: SecretStream.XChaCha20Poly1305.Tag = isFinal ? .FINAL : .MESSAGE;

        var cipherText =  [UInt8](repeating: 0, count: clearText.count + Int(crypto_secretstream_xchacha20poly1305_abytes()))
       
        var result: Int32 = -1
        result = crypto_secretstream_xchacha20poly1305_push(
            &state,
            &cipherText,
            nil,
            clearText,
            UInt64(clearText.count),
            nil,
            0,
            tag.rawValue
        )
        if result != 0 {
            print("Failed to encrypt clearText.")

        }
        return cipherText
    }
}

public class DIDSSDecrypt: DecryptionStream {
    
    private var state: crypto_secretstream_xchacha20poly1305_state
    private var complete: Bool

    init(_ key: [UInt8], _ header: [UInt8]) throws { // 参数类型不确定

        state = crypto_secretstream_xchacha20poly1305_state()

        var result: Int32 = -1
        result = crypto_secretstream_xchacha20poly1305_init_pull(
            &state,
            header,
            key
        )
        
        if result != 0 {
            print("Failed to init decryption.")
        }
        self.complete = false
    }

    public override func pull(_ cipherText: [UInt8]) throws -> [UInt8] {
        
        let ABytes = Int(crypto_secretstream_xchacha20poly1305_abytes())
        var message = [UInt8](repeating: 0, count: cipherText.count - ABytes)

        var _tag: UInt8 = 0
        
        var result: Int32 = -1
        result = crypto_secretstream_xchacha20poly1305_pull(
            &state,
            &message,
            nil,
            &_tag,
            cipherText,
            UInt64(cipherText.count),
            nil,
            0
        )

        if result != 0 {
            print("Failed to decrypt the cipherText.")
        }
        
        if _tag == SecretStream.XChaCha20Poly1305.Tag.FINAL.rawValue {
            self.complete = true
        }
        
        return message
    }

    public override func isComplete() -> Bool {
        return self.complete
    }
}
