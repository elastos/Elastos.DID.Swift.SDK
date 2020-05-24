
import UIKit

class JwtParserBuilder: NSObject {

    var claimsJwt : String?

    public func parseClaimsJwt(_ claimsJwt: String) throws -> JWT {
        return try JWT(jwtString: claimsJwt)
    }

    public func build() -> JwtParser {
        return JwtParser()
    }
}

public class JwtParser: NSObject {

    var jwt: JWT?

    public func parseClaimsJwt(_ claimsJwt: String) throws -> JWT {
        return try JWT(jwtString: claimsJwt)
    }


    public func getHeader() throws -> Header {
        return jwt!.header;
    }

    public func getBody() throws -> Claims {
        return jwt!.claims;
    }
}
