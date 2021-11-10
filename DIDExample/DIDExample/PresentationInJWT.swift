import UIKit
import ElastosDIDSDK

class PresentationInJWT: NSObject {

    override init() {
        do {
            // Initializa the DID backend globally.
//            try DIDBackend.initialize(AssistDIDAdapter(network: "testnet"))
            try DIDBackend.initialize(AssistDIDAdapter(network: "mainnet")) 
            let university = JWTUniversity(name: "Elastos")
            let student = try JWTStudent("John Smith", "Male", "johnsmith@example.org")
            
            var vc = try university.issueDiplomaFor(student)
            print("The diploma credential:")
            print("  \(vc)")
            print("  Genuine: \(try vc.isGenuine())")
            print("  Expired: \(try vc.isExpired())")
            print("  Valid: \(try vc.isValid())")
            student.addCredential(vc)
            
            vc = try student.createSelfProclaimedCredential()
            print("The profile credential:")
            print("  \(vc)")
            print("  Genuine: \(try vc.isGenuine())")
            print("  Expired: \(try vc.isExpired())")
            print("  Valid: \(try vc.isValid())")
            student.addCredential(vc)
            
            var vp = try student.createPresentation("test", "873172f58701a9ee686f0630204fee59")
            print("The verifiable presentation:")
            print("  \(vp)")
            print("  Genuine: \(try vp.isGenuine())")
            print("  Valid: \(try vp.isValid())")
            
            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10
            
            // Create JWT token with presentation.
            let token = try student.getDocument().jwtBuilder()
                .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                .setId(id: "test00000000")
                .setAudience(audience: university.getDid.description)
                .setIssuedAt(issuedAt: iat!)
                .setNotBefore(nbf: nbf)
                .setExpiration(expiration: exp)
                .claimWithJson(name: "presentation", jsonValue: vp.description)
                .sign(using: student.storepass)
                .compact()

            print("JWT Token:")
            print("  \(token)")
            
            // Verify the token automatically
            var jp = try JwtParserBuilder().build()
            var jwt = try jp.parseClaimsJwt(token)
            
            // Get claims from the token
            let preJson = try jwt.claims.getAsJson(key: "presentation")
            vp = try VerifiablePresentation.fromJson(preJson)
            print("Presentation from JWT:")
            print("  \(vp)")
            print("  Genuine: \(try vp.isGenuine())")
            print("  Valid: \(try vp.isValid())")
            
            // Verify the token based on a DID
            // This will success, because the JWT was signed by the student
            jp = try student.getDocument().jwtParserBuilder().build()
            jwt = try jp.parseClaimsJwt(token)
            
            // This will failed, because the JWT was signed by the student not by the university
            jp = try university.getDocument().jwtParserBuilder().build()
            do {
                jwt = try jp.parseClaimsJwt(token)
            } catch {
                // Should be here.
            }
        } catch {
            print("PresentationInJWT init error: \(error)")
        }
    }
}

public class PresentationInJWTEntity: NSObject {
    // Mnemonic passphrase and the store password should set by the end user.
    let passphrase = "mypassphrase"
    let storepass = "mypassword"
    
    var name: String = ""
    var store: DIDStore!
    var did: DID!
    
    init(name: String) {
        self.name = name
        super.init()
        try! initPrivateIdentity()
        try! initDid()
    }
    
    func initPrivateIdentity() throws {
        
        let storePath = "\(NSHomeDirectory())/Library/Caches/data/didCache/" + name + ".store"
        store = try DIDStore.open(atPath: storePath)
        
        // Check the store whether contains the root private identity.
        if (try store.containsRootIdentities()) {
            return // Already exists
        }
        
        let mnemonic = try! Mnemonic.generate(Mnemonic.DID_ENGLISH)
        print("Please write down your mnemonic and passwords:")
        print("  Mnemonic: \(mnemonic)")
        print("  Mnemonic passphrase: \(passphrase)")
        print("  Store password: \(storepass)")
        _ = try RootIdentity.create(mnemonic, passphrase, store, storepass)
    }
    
    func initDid() throws {
        
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

class JWTUniversity: PresentationInJWTEntity {
    var issuer: VerifiableCredentialIssuer?

   override init(name: String) {
       super.init(name: name)
       issuer = try! VerifiableCredentialIssuer(getDocument())
    }
    
    func issueDiplomaFor(_ student: JWTStudent) throws -> VerifiableCredential {
        let subject = ["name": student.name, "degree": "bachelor", "institute": "Computer Science", "university": name]
        let userCalendar = Calendar.current
        var components = DateComponents()
        components.year = 2025
        let exp = userCalendar.date(from: components)
        let cb = issuer!.editingVerifiableCredentialFor(did: student.did)
        let vc = try cb.withId("diploma")
            .withTypes("DiplomaCredential")
            .withProperties(subject)
            .withExpirationDate(exp!)
            .seal(using: storepass)

        print("VerifiableCredential:")
        let vcStr = vc.toString(true)
        print(vcStr)

        return vc
    }
}

public class JWTStudent: PresentationInJWTEntity {
    public var gender: String
    public var email: String
    public var vcs: [VerifiableCredential] = []

    public init(_ name: String, _ gender: String, _ email: String) throws {
        self.gender = gender
        self.email = email
        super.init(name: name)
    }

    public func createSelfProclaimedCredential() throws -> VerifiableCredential {
        let subject = ["name": name, "gender": gender, "email": email]
        let userCalendar = Calendar.current
        var components = DateComponents()
        components.year = 2020
        components.month = 9
        components.day = 14
        components.minute = 21
        components.hour = 21
        components.second = 41
        let iat = userCalendar.date(from: components)

        let exp = iat! + 100000000000
        let cb = try VerifiableCredentialIssuer(getDocument()).editingVerifiableCredentialFor(did: did)
        let vc = try cb.withId("profile")
            .withTypes("ProfileCredential", "SelfProclaimedCredential")
            .withProperties(subject)
            .withExpirationDate(exp)
            .seal(using: storepass)

        return vc
    }
    
    public func addCredential(_ vc: VerifiableCredential) {
        vcs.append(vc)
    }
    
    public func createPresentation(_ realm: String, _ nonce: String) throws -> VerifiablePresentation {
        let vpb = try VerifiablePresentation.editingVerifiablePresentation(for: self.did!, using: self.store!)
        let vp = try vpb.withCredentials(vcs)
            .withRealm(realm)
            .withNonce(nonce)
            .seal(using: storepass)
        
        print("VerifiableCredential: ")
        print(vp.description)
        
        return vp
    }
}
