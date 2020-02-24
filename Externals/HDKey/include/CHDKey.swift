import Foundation

internal struct CHDKey {
    var fingerPrint: UInt32?
    
    var chainCodeForSk: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    var privateKey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    var chainCodeForPk: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    var publicKey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    init() {}
}

internal struct CDerivedKey {

    var publicKey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    var privatekey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    var address: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    init() {}
}

@_silgen_name("HDKey_GenerateMnemonic")
internal func HDKey_GenerateMnemonic(_ language: Int32) -> UnsafePointer<Int8>!

@_silgen_name("HDKey_FreeMnemonic")
internal func HDKey_FreeMnemonic(_ mnemonic: UnsafePointer<Int8>)

@_silgen_name("HDKey_MnemonicIsValid")
internal func HDKey_MnemonicIsValid(_ mnemonic: UnsafePointer<Int8>,
                                 _ language: Int32) -> Bool

@_silgen_name("HDKey_FromMnemonic")
internal func HDKey_FromMnemonic(_ mmemonic: UnsafePointer<Int8>,
                                 _ passphrase: UnsafePointer<Int8>,
                                 _ language: Int8!,
                                 _ hdKey: UnsafePointer<CHDKey>) -> UnsafeMutablePointer<CHDKey>

@_silgen_name("HDKey_FromSeed")
internal func HDKey_FromSeed(_ seed: UnsafeMutablePointer<Int8>,
                                 _ size: Int,
                                 _ hdKey: UnsafePointer<CHDKey>) -> UnsafeMutablePointer<CHDKey>

@_silgen_name("HDKey_FromExtendedKey")
internal func HDKey_FromExtendedKey(_ extendedKey: UnsafeMutablePointer<Int8>,
                                 _ size: Int,
                                 _ hdkey: UnsafePointer<CHDKey>) -> UnsafeMutablePointer<CHDKey>

@_silgen_name("HDKey_Serialize")
internal func HDKey_Serialize(_ hdkey: UnsafePointer<CHDKey>,
                                 _ extendedKey: UnsafePointer<Int8>,
                                 _ size: Int) -> Int

@_silgen_name("HDKey_Wipe")
internal func HDKey_Wipe(_ hdkey: UnsafePointer<CHDKey>)

@_silgen_name("HDKey_PublicKey2Address")
internal func HDKey_PublicKey2Address(_ publicKey: UnsafePointer<Int8>,
                                 _ address: UnsafePointer<Int8>,
                                 _ len: Int) -> UnsafeMutablePointer<Int8>

@_silgen_name("HDKey_GetDerivedKey")
internal func HDKey_GetDerivedKey( _ hdKey: UnsafePointer<CHDKey>,
                                 _ index: Int,
                                 _ derivedKey: UnsafePointer<CDerivedKey>) -> UnsafeMutablePointer<CDerivedKey>

@_silgen_name("DerivedKey_GetPublicKey")
internal func DerivedKey_GetPublicKey(_ derivedKey: UnsafePointer<CDerivedKey>) ->UnsafePointer<Int8>

@_silgen_name("DerivedKey_GetPublicKeyBase")
internal func DerivedKey_GetPublicKeyBase58(_ derivedKey: UnsafePointer<CDerivedKey>,
                                 _ base: UnsafePointer<Int8>!,
                                 _ size: Int32!) -> UnsafePointer<Int8>

@_silgen_name("DerivedKey_GetPrivateKey")
internal func DerivedKey_GetPrivateKey(_ drivedKey: UnsafePointer<CDerivedKey>) -> UnsafePointer<Int8>

@_silgen_name("DerivedKey_GetAddress")
internal func DerivedKey_GetAddress(_ derivedkey: UnsafePointer<CDerivedKey>) -> UnsafePointer<Int8>

@_silgen_name("DerivedKey_Wipe")
internal func DerivedKey_Wipe(_ derivedKey: UnsafePointer<CDerivedKey>)
