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

/// The inferface to change password.
//protocol ReEncryptor {
//
//    /// Reencrypt in the changing password.
//    /// - Parameter data: the data need to reencrypted
//    /// - Return: the reencrypted data
//    func containsPrivateIdentity(_ data: String) -> String
//}

/// The interface for DIDStorage to support different file system.
protocol DIDStorage {
    
    func getLocation() -> String
    
    /// Store private identity.
    func storeRootIdentity(_ id: String, _ mnemonic: String?, _ privateKey: String?, _ publicKey: String?, _ index: Int) throws
    
    /// Load private identity.
    func loadRootIdentity(_ id: String) throws -> RootIdentity?
    func loadRootIdentityPrivateKey(_ id: String) throws -> String?
    /// Load mnemonic.
    func loadRootIdentityMnemonic(_ id: String) throws -> String
    func updateRootIdentityIndex(_ id: String, _ index: Int) throws
    func deleteRootIdentity(_ id: String) throws -> Bool
    func listRootIdentities() throws -> [RootIdentity]
    func containsRootIdenities() throws -> Bool

    // Metadata
    func storeMetadata(_ metadata: DIDStoreMetadata) throws
    func loadMetadata() throws -> DIDStoreMetadata?
    func storeRootIdentityMetadata(_ id: String, _ metadata: RootIdentityMetadata) throws
    /// Load DID Metadata.
    /// - Parameter id: the owner of Metadata.
    /// - Return: the meta data
    func loadRootIdentityMetadata(_ id: String) throws -> RootIdentityMetadata?
    
    func storeDidMetadata(_ did: DID, _ meta: DIDMetadata) throws
    func loadDidMetadata(_ did: DID) throws -> DIDMetadata?

    // DIDS
    func storeDid(_ doc: DIDDocument) throws
    func loadDid(_ did: DID) throws -> DIDDocument?
    func deleteDid(_ did: DID) -> Bool
    func listDids() throws -> Array<DID>
    func listPrivateKeys(_ did: DID) throws -> Array<DIDURL>

    // Credentials
    func storeCredentialMetadata(_ id: DIDURL, _ metadata: CredentialMetadata) throws
    func loadCredentialMetadata(_ id: DIDURL) throws -> CredentialMetadata?

    func storeCredential(_ credential: VerifiableCredential) throws

    func loadCredential(_ id: DIDURL) throws -> VerifiableCredential?

    func containsCredentials(_ did: DID) -> Bool
    func deleteCredential(_ id: DIDURL) -> Bool

    func listCredentials(_ did: DID) throws -> Array<DIDURL>

    // Private keys
    func storePrivateKey(_ id: DIDURL, _ privateKey: String) throws

    func loadPrivateKey(_ id: DIDURL) throws -> String

    func containsPrivateKeys(_ did: DID) throws -> Bool
    func deletePrivateKey(_ id: DIDURL) -> Bool

//    func changePassword(_  callback: (String) throws -> String) throws// 0
    func changePassword(_  reEncryptor: ReEncryptor) throws

}
