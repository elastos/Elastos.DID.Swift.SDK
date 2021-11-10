import UIKit
import ElastosDIDSDK

class ParseJWT: NSObject {

    func printJwt(_ token: String) {
        
        let tokens = token.split(separator: ".")
        if (tokens.count != 2 && tokens.count != 3) {
            print("Invalid token: \(token)")
            return
        }
        
        var str  = "\(tokens[0]).\(tokens[1])"
        if token.count == 3 {
            str.append(contentsOf: tokens[2])
        }
        
        print("Token: \(token)")
        print("Plain: \(str)")
    }
    
    override init() {
        super.init()
        do {
            // Initializa the DID backend globally.
            try DIDBackend.initialize(AssistDIDAdapter(network: "testnet"))

            let token = "eyJ0eXAiOiJKV1QiLCJsaWJyYXJ5IjoiRWxhc3RvcyBESUQiLCJ2ZXJzaW9uIjoiMS4wIiwiY3R5IjoianNvbiJ9.eyJqdGkiOiIwIiwiYXVkIjoiVGVzdCBjYXNlcyIsImlzcyI6ImRpZDplbGFzdG9zOmlvQXdHU29ZZmZRUlhQTHFtdFlCRnNOelZrd1NkejZtYjciLCJmb28iOiJiYXIiLCJpYXQiOjE2MDAwODk3MDEsImV4cCI6MTAxNjAwMDg5NzAxLCJuYmYiOjE2MDAwODk2OTEsInN1YiI6Ikp3dFRlc3QifQ"
            printJwt(token)

            let jp = try JwtParserBuilder().build()
            let jwt = try jp.parseClaimsJwt(token)
            
            print("jwt: \(jwt)")
            print("header: \(jwt.header.description)")
            print("claim: \(jwt.claims.description)")
        }
        catch {
            print(" ParseJWT ERROR: \(error)")
        }
    }
}
