

import Foundation

public struct CHDKey {
    var fingerPrint: UInt32?
    
    var chainCodeForSk: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    var privatekey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    var chainCodeForPk: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    var publicKey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    init() {}
}

public struct CDerivedKey {
    
    var publicKey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    var privatekey: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    var address: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    init() {}
}

@_silgen_name("HDKey_GenerateMnemonic")
internal func HDKey_GenerateMnemonic(_ language: Int32) -> UnsafePointer<Int8>!

@_silgen_name("HDKey_MnemonicIsValid")
internal func HDKey_MnemonicIsValid(_ mnemonic: UnsafePointer<Int8>, _ language: Int32) -> Bool

/*
 HDKey *HDKey_FromMnemonic(const char *mnemonic, const char *passphrase,
 int language, HDKey *hdkey);
 
 uint8_t *HDKey_GetSeedFromMnemonic(const char *mnemonic,
 const char *mnemonicPassword, int language, uint8_t *seed);
 */
//@_silgen_name("HDKey_GetSeedFromMnemonic")
//internal func HDKey_GetSeedFromMnemonic(_ mmemonic: UnsafePointer<Int8>, _ mnemonicPasswordbase58: UnsafePointer<Int8>, _ language: Int8!,_ seed: UnsafeMutablePointer<Int8>!
//    ) ->  UnsafeMutablePointer<Int8>

@_silgen_name("HDKey_FromMnemonic")
internal func HDKey_FromMnemonic(_ mmemonic: UnsafePointer<Int8>, _ passphrase: UnsafePointer<Int8>, _ language: Int32!,_ hdkey: UnsafeMutablePointer<CHDKey>!
) ->  UnsafeMutablePointer<CHDKey>

/*
 HDKey *HDKey_FromSeed(const uint8_t *seed, size_t size, HDKey *hdkey);
 */
@_silgen_name("HDKey_FromSeed")
internal func HDKey_FromSeed(_ seed: UnsafePointer<UInt8>, _ size: Int32, _ hdkey: UnsafeMutablePointer<CHDKey>!
) ->  UnsafeMutablePointer<CHDKey>

/*
 HDKey *HDKey_FromExtendedKey(const uint8_t *extendedkey, size_t size, HDKey *hdkey);
 */
@_silgen_name("HDKey_FromExtendedKey")
internal func HDKey_FromExtendedKey(_ extendedkey: UnsafePointer<UInt8>, _ size: Int32, _ hdkey: UnsafeMutablePointer<CHDKey>!
) ->  UnsafeMutablePointer<CHDKey>

/*
 ssize_t HDKey_Serialize(HDKey *hdkey, uint8_t *extendedkey, size_t size);
 
 */
@_silgen_name("HDKey_Serialize")
internal func HDKey_Serialize(_ hdkey: UnsafeMutablePointer<CHDKey>, _ extendedkey: UnsafeMutablePointer<UInt8>, _ size: Int32) -> Int32

/*
 void HDKey_Wipe(HDKey *hdkey);
 */
@_silgen_name("HDKey_Wipe")
internal func HDKey_Wipe(_ hdkey: UnsafeMutablePointer<CHDKey>)

/*
 char *HDKey_PublicKey2Address(uint8_t *publickey, char *address, size_t len);
 */
@_silgen_name("HDKey_PublicKey2Address")
internal func HDKey_PublicKey2Address(_ publickey: UnsafeMutablePointer<UInt8>,
                                      _ address: UnsafePointer<Int8>!,
                                      _ len: Int32) -> UnsafePointer<Int8>!

/*
 DerivedKey *HDKey_GetDerivedKey(HDKey* hdkey, int index, DerivedKey *derivedkey);
 */
@_silgen_name("HDKey_GetDerivedKey")
internal func HDKey_GetDerivedKey(_ hdkey: UnsafeMutablePointer<CHDKey>,
                                  _ index: Int32,
                                  _ derivedkey: UnsafeMutablePointer<CDerivedKey>) -> UnsafeMutablePointer<CDerivedKey>

/*
 uint8_t *DerivedKey_GetPublicKey(DerivedKey *derivedkey);
 */
@_silgen_name("DerivedKey_GetPublicKey")
internal func DerivedKey_GetPublicKey(_ derivedkey: UnsafeMutablePointer<CDerivedKey>) -> UnsafeMutablePointer<UInt8>

/*
 const char *DerivedKey_GetPublicKeyBase58(DerivedKey *derivedkey, char *base, size_t size);
 */
@_silgen_name("DerivedKey_GetPublicKeyBase58")
internal func DerivedKey_GetPublicKeyBase58(_ derivedkey: UnsafeMutablePointer<CDerivedKey>, _ base: UnsafeMutablePointer<Int8>, _ size: Int32) -> UnsafePointer<Int8>

/*
 uint8_t *DerivedKey_GetPrivateKey(DerivedKey *derivedkey);
 */
@_silgen_name("DerivedKey_GetPrivateKey")
internal func DerivedKey_GetPrivateKey(_ derivedkey: UnsafeMutablePointer<CDerivedKey>) -> UnsafeMutablePointer<UInt8>

/*
 char *DerivedKey_GetAddress(DerivedKey *derivedkey);
 */
@_silgen_name("DerivedKey_GetAddress")
internal func DerivedKey_GetAddress(_ derivedkey: UnsafeMutablePointer<CDerivedKey>) -> UnsafePointer<Int8>!

/*
 void DerivedKey_Wipe(DerivedKey *derivedkey);
 */
@_silgen_name("DerivedKey_Wipe")
internal func DerivedKey_Wipe(_ hdkey: UnsafeMutablePointer<CDerivedKey>)


/*
// HDKey *HDKey_GetPrivateIdentity(const uint8_t *seed, int coinType, HDKey *hdkey);
@_silgen_name("HDKey_GetPrivateIdentity")
internal func HDKey_GetPrivateIdentity(_ seed: UnsafeMutablePointer<Int8>,
                                       _ coinType: Int,
                                       _ hdkey: UnsafeMutablePointer<CHDKey>?) ->  UnsafePointer<CHDKey>

@_silgen_name("HDKey_GetSubPrivateKey")
internal func HDKey_GetSubPrivateKey(_ privateIdentity: UnsafePointer<CHDKey>,
                                     _ coinType: Int32!,
                                     _ chain: Int32!,
                                     _ index: Int32!,
                                     _ privatekey: UnsafeMutablePointer<Int8>) -> UnsafeMutablePointer<Int8>

@_silgen_name("HDKey_GetSubPublicKey")
internal func HDKey_GetSubPublicKey(_ privateIdentity: UnsafePointer<CHDKey>!,
                                    _ chain: Int32!,
                                    _ index: Int32!,
                                    _ publickey: UnsafeMutablePointer<Int8>!) -> UnsafeMutablePointer<Int8>!

@_silgen_name("HDKey_GetDerivedKey")
internal func HDKey_GetDerivedKey(_ privateIdentity: UnsafePointer<CHDKey>,
                                  _ derivedkey: UnsafeMutablePointer<CDerivedKey>,
                                  _ coinType: Int32!,
                                  _ chain: Int32!,
                                  _ index: Int32!) ->  UnsafePointer<CDerivedKey>

@_silgen_name("DerivedKey_GetAddress")
internal func DerivedKey_GetAddress(_ derivedkey: UnsafePointer<CDerivedKey>) -> UnsafePointer<Int8>!

//char *HDKey_GetAddress(uint8_t *publickey, char *address, size_t len);
@_silgen_name("HDKey_GetAddress")
internal func HDKey_GetAddress(_ publickey: UnsafeMutablePointer<Int8>, _ address: UnsafeMutablePointer<Int8>, _ size_t: Int32) -> UnsafeMutablePointer<Int8>
*/
