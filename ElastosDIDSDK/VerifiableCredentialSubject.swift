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

import Foundation
import ObjectMapper

@objc(VerifiableCredentialSubject)
/// The object keeps the credential subject contents.
public class VerifiableCredentialSubject: NSObject, Mappable {
    
    public required init?(map: Map) {

    }
    
    public func mapping(map: Map) {
        _id = try! DID(map.value("id") as String)
        var dic: Dictionary<String, Any> = [:]
        for (item) in map.JSON.enumerated() {
            if item.element.key != "id" {
                dic[item.element.key] = item.element.value
            }
        }
        _properties = JsonNode(dic)
    }
    
    private let TAG = NSStringFromClass(VerifiableCredentialSubject.self)
    private var _id: DID?
    private var _properties: JsonNode = JsonNode()
    private let ID = "id"

    init(_ id: DID) {
        self._id = id
    }

    /// Get id property from Credential.
    @objc
    public var did: DID {
        return self._id!
    }
    
    func setId(_ newVaule: DID) {
        self._id = newVaule
    }

    /// Get count of subject properties in Credential.
    @objc
    public var propertyCount: Int {
        return self._properties.count
    }

    /// Get string of subject properties in Credential.
    /// - Returns: properties as string.
    @objc
    public func getPropertiesAsString() -> String {
        return self._properties.toString()
    }

    /// Get array of subject properties in Credential.
    /// - Returns: Array of credential
    @objc
    public func getProperties() -> JsonNode? {
        return self._properties.deepCopy()
    }
    
    
    /// Get array of subject properties in Credential.
    /// - Returns: Array of credential
    @objc
    public func properties() -> [String: Any]? {
        let proStr = _properties.toString()
        
        return proStr.toDictionary()
    }

    /// Get specified subject property according to the key of property.
    /// - Parameter ofName: The key of property.
    /// - Returns: properties as string.
    @objc
    public func getPropertyAsString(ofName: String) -> String? {
        return self._properties.get(forKey: ofName)?.toString()
    }

    /// Get specified subject property according to the key of property.
    /// - Parameter ofName: The key of property.
    /// - Returns: properties as string.
    @objc
    public func getProperty(ofName: String) -> JsonNode? {
        return self._properties.get(forKey: ofName)
    }
    
    /// Get specified subject property according to the key of property.
    /// - Parameter ofName: The key of property.
    /// - Returns: properties as string.
    @objc
    public func property(ofName: String) -> [String: Any]? {
        return self._properties.get(forKey: ofName)?.asDictionary()
    }
    
    func setProperties(_ properties: JsonNode) {
        self._properties = properties.deepCopy()!
        // remote ID field, avoid conflict with subject's id property.
        self._properties.remove("id")
    }
    
    func setProperties(_ name: String, _ value: Any) {
        
        guard name != ID else {
            return
        }
        _properties.setValue(value, forKey: name)
    }

    class func fromJson(_ node: JsonNode, _ ref: DID?) throws -> VerifiableCredentialSubject {
        let serializer = JsonSerializer(node)
        let options    = JsonSerializer.Options()
                                    .withOptional(ref != nil)
                                    .withRef(ref)
                                    .withHint("credentialSubject id")
                                    .withError() { (des) -> DIDError in
                                        return DIDError.malformedCredential(des)
                                    }
        let did = try serializer.getDID(Constants.ID, options)

        let credential = VerifiableCredentialSubject(did)
        credential.setProperties(node)
        return credential
    }

    func toJson(_ generator: JsonGenerator, _ ref: DID?, _ normalized: Bool) {
        generator.writeStartObject()

//        if normalized || ref == nil || self.did != ref! {
        generator.writeStringField(Constants.ID, self.did.toString())
//        }

        if self.propertyCount > 0 {
            toJson(generator, self._properties, true)
        }

        generator.writeEndObject()
    }

    func toJson(_ generator: JsonGenerator, _ node: JsonNode) {
        toJson(generator, node, false)
    }

    func toJson(_ generator: JsonGenerator, _ node: JsonNode, _ objectContext: Bool) {
        switch node.getNodeType() {
        case .ARRAY:
            generator.writeStartArray()
            let elems: [JsonNode] = node.asArray()!
            for elem in elems {
                toJson(generator, elem)
            }
            generator.writeEndArray()
            break

        case .STRING:
            generator.writeString(node.asString()!)
            break

        case .NUMBER:
            generator.writeNumber(node.asNumber()!)
            break

        case .BOOLEAN:
            generator.writeBool(node.asBool()!)
            break

        case .DICTIONARY:
            if !objectContext {
                generator.writeStartObject()
            }
            let dictionary: [String: JsonNode] = node.asDictionary()!
            let sortedKeys = dictionary.keys.sorted()
            for key in sortedKeys {
                if key == "booleanValue" {    
                }
                generator.writeFieldName(key)
                toJson(generator, node.get(forKey: key)!)
            }
            if !objectContext {
                generator.writeEndObject()
            }

            break
        default: break

        }
    }
}
