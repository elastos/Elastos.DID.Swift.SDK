
import UIKit

class JwtParserBuilder: NSObject {

    public func parseClaimsJwt(_ claimsJwt: String) throws -> JWT {
        return try JWT(jwtString: claimsJwt)
    }
}
