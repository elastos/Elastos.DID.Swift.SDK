import UIKit
import ElastosDIDSDK

class InitializeDID: NSObject {
    // Mnemonic passphrase and the store password should set by the end user.
    let passphrase = "mypassphrase"
    let storepass = "mypassword"

    var store: DIDStore!
    
    override init() {
        do {
            super.init()
            try initDIDBackend()
            try initRootIdentity()
            try initDid()
        } catch {
           print("InitializeDID error: \(error)")
        }
    }
    private func initDIDBackend() throws {
        // Initialize the DID backend globally.
        try DIDBackend.initialize(AssistDIDAdapter(network: "mainnet"))
    }
    
    func initRootIdentity() throws {
        let storePath = "\(NSHomeDirectory())/Library/Caches/data/didCache/" + "exampleStore"
        store = try DIDStore.open(atPath: storePath)
        if (try store.containsRootIdentities()) {
            return // Already exists
        }
        
        // Create a mnemonic use default language(English).
        let mnemonic = try! Mnemonic.generate(Mnemonic.DID_ENGLISH)
        
        // Initialize the root identity.
        _ = try RootIdentity.create(mnemonic, passphrase, store!, storepass)
    }

    func initDid() throws {
//        let dids = try store!.listDids()
        let dids = try store!.listDids(DIDExFilter())
        if (dids.count > 0) {
            return
        }
        let id = try store.loadRootIdentity()
        let doc = try id!.newDid(storepass)
        doc.getMetadata().setAlias("me")
        print("My new DID created: \(doc.subject)")
        try doc.publish(using: storepass)
    }
}

class DIDExFilter: DIDFilter{
    func accept(_ did: DID) -> Bool {
        return did.getMetadata().getAlias() == "me"
    }
}
