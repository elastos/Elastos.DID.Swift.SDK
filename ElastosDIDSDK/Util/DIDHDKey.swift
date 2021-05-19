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

@objc(DIDHDKey)
public class DIDHDKey: NSObject {
    @objc public static let DID_PUBLICKEY_BYTES : Int = 33
    @objc public static let DID_PRIVATEKEY_BYTES: Int = 32
    @objc public static let DID_SEED_BYTES: Int = 64
    @objc public static let DID_EXTENDED_KEY_BYTES = 82
    @objc public static let DID_EXTENDED_PRIVATEKEY_BYTES = DID_EXTENDED_KEY_BYTES
    @objc public static let DID_EXTENDED_PUBLICKEY_BYTES = DID_EXTENDED_KEY_BYTES

    private static let DID_PADDING_IDENTITY = 0x67
    private static let DID_PADDING_STANDARD = 0xAD
    
    private var key: UnsafePointer<CHDKey>

    // Derive path: m/44'/0'/0'/0/index
    @objc public static let DID_DERIVE_PATH_PREFIX = "44H/0H/0H/0/"

    // Pre-derive publickey path: m/44'/0'/0'
    @objc public static let DID_PRE_DERIVED_PUBLICKEY_PATH = "44H/0H/0H"

    let DID_PUBLICKEY_BASE58_BYTES = 66

    required init(_ key: UnsafePointer<CHDKey>) {
        self.key = key
        super.init()
    }

    @objc
    public convenience init(_ mnemonic: String, _ passPhrase: String, _ language: String) {
        let cmnemonic = mnemonic.toUnsafePointerInt8()!
        let cpassphrase = passPhrase.toUnsafePointerInt8()!
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let key = HDKey_FromMnemonic(cmnemonic, cpassphrase, language.toUnsafePointerInt8()!, chdKey)
        self.init(key)
    }

    @objc
    public convenience init(_ seed: Data) {
        let cseed: UnsafePointer<UInt8> = seed.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }

        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let chdkey = HDKey_FromSeed(cseed, Int32(seed.count), chdKey)
        self.init(chdkey)
    }

    @objc
    public func getPrivateKeyBytes() -> [UInt8] {
        let privatekeyPointer = HDKey_GetPrivateKey(key)
        let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: DIDHDKey.DID_PRIVATEKEY_BYTES)
        let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)

        return [UInt8](privatekeyData)
    }

    @objc
    public func getPrivateKeyData() -> Data {
        let privatekeyPointer = HDKey_GetPrivateKey(key)
        let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: DIDHDKey.DID_PRIVATEKEY_BYTES)

        return Data(buffer: privatekeyPointerToArry)
    }

    @objc
    public func getPrivateKeyBase58() -> String {
        return Base58.base58FromBytes(getPrivateKeyBytes())
    }

    @objc
    public func getPublicKeyBytes() ->[UInt8] {
        let cpublicKeyPointer = HDKey_GetPublicKey(key)
        let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: DIDHDKey.DID_PUBLICKEY_BYTES)
        let publicKeyData: Data = Data(buffer: publicKeyPointerToArry)

        return [UInt8](publicKeyData)
    }

    @objc
    public func getPublicKeyData() -> Data {
        let cpublicKeyPointer = HDKey_GetPublicKey(key)
        let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: DIDHDKey.DID_PUBLICKEY_BYTES)

        return Data(buffer: publicKeyPointerToArry)
    }

    @objc
    public func getPublicKeyBase58() -> String {
        let basePointer: UnsafeMutablePointer<CChar> = UnsafeMutablePointer<CChar>.allocate(capacity: DID_PUBLICKEY_BASE58_BYTES)
        let cpublickeybase58 = HDKey_GetPublicKeyBase58(key, basePointer, Int32(DID_PUBLICKEY_BASE58_BYTES))
        print(String(cString: cpublickeybase58))
        return String(cString: cpublickeybase58)
    }

    @objc
    public func serialize() throws -> Data {
        let data = Base58.bytesFromBase58(serializeBase58())
        return Data(bytes: data, count: data.count)
    }

    @objc
    public func serializeBase58() -> String {
        let extendedkeyPointer: UnsafeMutablePointer<CChar> = UnsafeMutablePointer<CChar>.allocate(capacity: 512)
        let cextendedkey = HDKey_SerializePrvBase58(key, extendedkeyPointer, 512)
        
        return String(cString: cextendedkey!)
    }

    @objc
    public func serializePublicKey() throws -> [UInt8] {
        return try Base58.bytesFromBase58(serializePublicKeyBase58())
    }

    @objc
    public func serializePublicKeyBase58() throws -> String {

        let extendedkeyPointer: UnsafeMutablePointer<CChar> = UnsafeMutablePointer<CChar>.allocate(capacity: 256)
        let cextendedkey = HDKey_SerializePubBase58(key, extendedkeyPointer,Int32(256))
        guard let _ = cextendedkey else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("HDKey_SerializePubBase58 error.")
        }

        return String(cString: cextendedkey!)
    }

    @objc
    public class func deserialize(_ keyData: [UInt8]) -> DIDHDKey {
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let cdata: UnsafePointer<UInt8> = Data(bytes: keyData, count: keyData.count).withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        let k = HDKey_Deserialize(chdKey, cdata, Int32(keyData.count))
        return self.init(k)
    }

    @objc(deserializeWithKeyData:)
    public class func deserialize(_ keyData: Data) -> DIDHDKey {
        let extendedkeyData = keyData
        let cextendedkey = extendedkeyData.withUnsafeBytes { re -> UnsafePointer<UInt8> in
            return re
        }
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let hdkey = HDKey_FromExtendedKey(cextendedkey, Int32(extendedkeyData.count), chdKey)
        return self.init(hdkey)
    }

    @objc
    public class func deserializeBase58(_ keyData: String) -> DIDHDKey {
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let hdkey = HDKey_DeserializeBase58(chdKey, keyData.toUnsafePointerInt8()!, Int32(keyData.count))
        return self.init(hdkey)
    }

    @objc
    public class func paddingToExtendedPrivateKey(_ privateKeyBytes: Data) -> Data {
        var pkData: Data = privateKeyBytes
        let cpks = pkData.withUnsafeBytes { (bytes) -> UnsafePointer<UInt8> in
            return bytes
        }
        let cextenedkey: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: DID_EXTENDED_PRIVATEKEY_BYTES)

        _ = HDKey_PaddingToExtendedPrivateKey(cpks, 32, cextenedkey, UInt32(DID_EXTENDED_PRIVATEKEY_BYTES))
        let extenedToArrary: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cextenedkey, count: DID_EXTENDED_PRIVATEKEY_BYTES)
        let extenedData: Data = Data(buffer: extenedToArrary)

        return extenedData
//        return [UInt8](extenedData)
    }

    @objc
    public func derive(_ path: String) throws -> DIDHDKey {
        let cderivedkey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 256)
        let childNum = try childList(path)
        let hkey = HDKey_GetvDerivedKey(key, cderivedkey, Int32(childNum.count), getVaList(childNum))

        return DIDHDKey(hkey)
    }

    // "44H/0H/0H"
    private func childList(_ path: String) throws -> [CVarArg] {
        var childNum: [CVarArg] = []
        let arraySubstrings: [Substring] = path.split(separator: "/")
        try arraySubstrings.forEach { str in
            if (str.suffix(1) == "H") {
                let v = String(str.prefix(str.count - 1))
                let iV: UInt32 = try UInt32(value: v)
                let value = iV | 0x80000000
                childNum.append(value)
            }
            else {
                let iV: UInt32 = try UInt32(value: String(str))
                childNum.append(UInt32(iV))
            }
        }

        return childNum
    }

    @objc
    public func derive(_ index: Int, _ hardened: Bool) -> DIDHDKey {
        var childNum: [CVarArg] = []
        let cderivedkey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 256)
        if hardened {
            childNum.append(UInt32(index) | 0x80000000)
        }
        else {
            childNum.append(index)
        }
        let hkey = HDKey_GetvDerivedKey(key, cderivedkey, Int32(childNum.count), getVaList(childNum))

        return DIDHDKey(hkey)
    }

    @objc
    public func derive(_ index: Int) -> DIDHDKey {

        return derive(index, false)
    }

    @objc
    public func getAddress() -> String {
        let cid = HDKey_GetAddress(self.key)
        return (String(cString: cid!))
    }

    @objc
    public class func toAddress(_ pk: [UInt8]) -> String {
        let pkData: Data = Data(bytes: pk, count: pk.count)
        let cpks = pkData.withUnsafeBytes { (bytes) -> UnsafePointer<UInt8> in
            return bytes
        }
        let address: UnsafeMutablePointer<CChar> = UnsafeMutablePointer<CChar>.allocate(capacity: 48)
        let cid = HDKey_PublicKey2Address(cpks, address, 48)

        return (String(cString: cid!))
    }

    class func PEM_ReadPublicKey(_ publicKey: Data) throws -> String {
        let cpub: UnsafePointer<UInt8> = publicKey.withUnsafeBytes { (bytes) -> UnsafePointer<UInt8> in
            return bytes
        }
        let cprivateKey: UnsafeMutablePointer<CChar> = UnsafeMutablePointer<CChar>.allocate(capacity: 512)
        var size: Int32 = 512
        let re = PEM_WritePublicKey(cpub, cprivateKey, &size)
        if re < 0 {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("PEM_ReadPublicKey error.")
        }
        let cstr = String(cString: cprivateKey)
        return cstr
    }

    class func PEM_ReadPrivateKey(_ publicKey: Data, _ privatekey: Data) throws -> String {
        let cpub: UnsafePointer<UInt8> = publicKey.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        let cpri: UnsafePointer<UInt8> = privatekey.withUnsafeBytes { bytes
            -> UnsafePointer<UInt8> in
            return bytes
        }
        let cPEM_privateKey: UnsafeMutablePointer<CChar> = UnsafeMutablePointer<CChar>.allocate(capacity: 512)
        var count = 512
        let re = PEM_WritePrivateKey(cpub, cpri, cPEM_privateKey, &count)
        if re < 0 {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("PEM_ReadPublicKey error.")
        }
        let cstr = String(cString: cPEM_privateKey)
        return cstr
    }

    func wipe() {
        HDKey_Wipe(UnsafeMutablePointer<CHDKey>(mutating: key))
    }
}
