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

public struct DIDCurve25519KeyPair {
    var ed25519Sk: [UInt8]
    var ed25519Pk: [UInt8]
    var privateKey: [UInt8]
    var publicKey: [UInt8]
}

public class CryptoUtils {

    public static func getCurve25519KeyPair(_ key: [UInt8]) throws -> DIDCurve25519KeyPair {
        
        let sodium = Sodium()

        // ED25519
        let edKeyPair = sodium.sign.keyPair(seed: key)
        if (edKeyPair == nil) {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Failed to generate ed25519 key pair.")
        }
        
        var pk = Bytes(repeating: 0, count: Int(crypto_kx_publickeybytes()))
        var sk = Bytes(repeating: 0, count: Int(crypto_kx_secretkeybytes()))

        _ = crypto_sign_ed25519_pk_to_curve25519(&pk, edKeyPair!.publicKey)
        _ = crypto_sign_ed25519_sk_to_curve25519(&sk, edKeyPair!.secretKey)

        return DIDCurve25519KeyPair(
            ed25519Sk: edKeyPair!.secretKey,
            ed25519Pk: edKeyPair!.publicKey,
            privateKey: sk,
            publicKey: pk
        )
    }
    
}
