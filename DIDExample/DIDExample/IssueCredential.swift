import UIKit
import ElastosDIDSDK

class IssueCredential: NSObject {
    
    override init() {
        let example = InitializeDID()
        
        do {
            // Initializa the DID backend globally.
//            try DIDBackend.initialize(AssistDIDAdapter(network: "testnet"))
            try DIDBackend.initialize(AssistDIDAdapter(network: "mainnet")) 
            try example.initRootIdentity()
            try example.initDid()
        } catch {
            print("IssueCredential init error: \(error)")
        }
    }
}

public class IssueCredentialEntity: NSObject {
    // Mnemonic passphrase and the store password should set by the end user.
    let passphrase = "mypassphrase"
    let storepass = "mypassword"
    
    var name: String = ""
    var store: DIDStore!
    var did: DID!
    
    init(name: String) {
        self.name = name
        super.init()
        try! initRootIdentity()
        try! initDid()
    }
    
    func initRootIdentity() throws {
        
        let storePath = "\(NSHomeDirectory())/Library/Caches/data/didCache/" + name + ".store"
        store = try DIDStore.open(atPath: storePath)
        
        // Check the store whether contains the root private identity.
        if (try store.containsRootIdentities()) {
            return // Already exists
        }
        
        // Create a mnemonic use default language(English).
        let mnemonic = try! Mnemonic.generate(Mnemonic.DID_ENGLISH)
        print("Please write down your mnemonic and passwords:")
        print("  Mnemonic: \(mnemonic)")
        print("  Mnemonic passphrase: \(passphrase)")
        print("  Store password: \(storepass)")
        
        // Initialize the root identity.
        let identity = try RootIdentity.create(mnemonic, passphrase, store, storepass)
        let re = try identity.synchronize(0)
        print(re)
    }
    
    func initDid() throws {
        // Check the DID store already contains owner's DID(with private key).
        let dids = try! store.listDids()
        if (dids.count > 0) {
            self.did = dids[0]
            return
        }
        let identity = try! store.loadRootIdentity()
        let doc = try identity!.newDid(storepass)
        self.did = doc.subject
        doc.getMetadata().setAlias("swift-me")
        print("My new DID created: ", name, did.description)
        try! doc.publish(using: storepass)
    }
    
    var getDIDStore: DIDStore {
        return store
    }
    
    var getDid: DID {
        return did
    }
    
    func getDocument() throws -> DIDDocument  {
        return try store.loadDid(did)!
    }
    
    var getName: String {
        return name
    }
    
    var getStorePassword: String {
        return storepass
    }
    
    public override var description: String {
        
        return did.description
    }
}


class IssueUniversity: IssueCredentialEntity {
    var issuer: VerifiableCredentialIssuer?

   override init(name: String) {
       super.init(name: name)
       issuer = try! VerifiableCredentialIssuer(getDocument())
    }
    
    func issueDiplomaFor(_ student: IssueStudent) throws -> VerifiableCredential {
        let subject = ["name": student.name, "degree": "bachelor", "institute": "Computer Science", "university": name]
        let userCalendar = Calendar.current
        var components = DateComponents()
        components.year = 2027
        let exp = userCalendar.date(from: components)
        let cb = issuer!.editingVerifiableCredentialFor(did: student.did)
        let vc = try cb.withId("diploma")
            .withType("DiplomaCredential", "https://ttech.io/credentials/diploma/v1")
            .withProperties(subject)
            .withExpirationDate(exp!)
            .seal(using: storepass)
        
        print("VerifiableCredential:")
        let vcStr = vc.toString(true)
        print(vcStr)
        
        return vc
    }
}

public class IssueStudent: IssueCredentialEntity {

    public init(_ name: String) throws {
        super.init(name: name)
    }
}
