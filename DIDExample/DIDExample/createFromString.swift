import UIKit
import ElastosDIDSDK

class createFromString: NSObject {

    override init() {
        super.init()
        do {
            try createFromString()
            try createFromParts()
            try createWithBuilder()
        }
        catch {
            print(error)
        }
    }
    
    func createFromString() throws {
        let urlString = "did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2#test"

        let url = try DIDURL(urlString)

        // output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2
        print(url.did)
        // output: test
        print(url.fragment)
    }
    
    func createFromParts() throws {
        let did = try DID("did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2")
        // create a url from a DID object and a relative url
        let url = try DIDURL(did, "/vcs/abc?opt=false&value=1#test")
        
        print(url.description)
        
        // output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2
        print(url.did)

        // output: /vcs/abc
        print(url.path)
        
        // output: opt=false&value=1
        print(url.queryString)

        // output: test
        print(url.fragment)
    }
    
    func createWithBuilder() throws {
        let did = try DID("did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2")
        let url = try DIDURLBuilder(did)
            .setPath("/vcs/abc")
            .setQueryParameters(["opt": "false", "value": "1"])
            .setFragment("test")
            .build()
    // output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2/vcs/abc?opt=false&value=1#test
        print(url.description)
        
        // output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2
        print(url.did)
        
        // output: /vcs/abc
        print(url.path)
        
        // output: opt=false&value=1
        print(url.queryString)
        
        // output: test
        print(url.fragment)
    }
}
