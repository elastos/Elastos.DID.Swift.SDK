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

/// A service endpoint may represent any type of service the subject wishes to advertise,
/// including decentralized identity management services for further discovery, authentication, authorization, or interaction.
@objc(Service)
public class Service: DIDObject {
    private let ID = "id"
    private let TYPE = "type"
    private let SERVICE_ENDPOINT = "serviceEndpoint"

    private var _endpoint: String
    private var _id: DIDURL
    private var _properties: JsonNode = JsonNode()
    private var _type: String
    
    /// Create a Service object with given values.
    /// - Parameters:
    ///   - id: the service id
    ///   - type: the service type
    ///   - endpoint: the service endpoint, could be URL or any application defined address
    ///   - properties: a map for the extra properties
    init(_ id: DIDURL, _ type: String, _ endpoint: String, _ properties: JsonNode) {
        self._endpoint = endpoint
        self._id = id
        self._type = type
        if properties.count != 0 {
            self._properties = properties
            self._properties.remove(ID)
            self._properties.remove(TYPE)
            self._properties.remove(SERVICE_ENDPOINT)
        }

        super.init(id, type)
    }
    
    /// Create a Service object with given values.
    /// - Parameters:
    ///   - id: the service id
    ///   - type: the service type
    ///   - endpoint: the service endpoint, could be URL or any application defined address
    init(_ id: DIDURL, _ type: String, _ endpoint: String) {
        self._endpoint = endpoint
        self._id = id
        self._type = type
        super.init(id, type)
    }
    
    /// Get the service id.
    @objc public var id: DIDURL {
        return _id
    }
    
    /// Get the service type.
    @objc public var type: String {
        return _type
    }
    /// Get the service endpoint.
    @objc public var endpoint: String {
        return _endpoint
    }
    
    /// Helper getter method for properties serialization.
    /// NOTICE: Should keep the alphabetic serialization order.
    /// a String to Object Dictionay include all application defined
    ///         properties
    @objc public var properties: [String: Any] {
       let proStr = _properties.toString()
        
        return proStr.toDictionary()
    }

    /// Get the specified property.
    /// - Parameter key: the property name
    /// - Returns: property value
    public func getProperty(_ key: String)  -> Any {
        let proStr = _properties.toString()
        let pros = proStr.toDictionary()
        
        return pros[key] as Any
    }
    
    /// Check whether the service has the specified property.
    /// - Parameter key: the property name
    /// - Returns: true if this service object has the specific property, false otherwise.
    public func hasProperty(_ key: String) -> Bool {
        let generator = JsonGenerator()
        generatorJson(generator, _properties)
        let prostr = generator.toString()
        print(prostr)
        let pros = prostr.toDictionary()
        
       return pros.keys.contains(key)
    }
    
    class func fromJson(_ node: JsonNode, _ ref: DID?) throws -> Service {
        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withRef(ref)
        guard let id = try serializer.getDIDURL(Constants.ID, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing service id")
        }

        options = JsonSerializer.Options()
        guard let type = try serializer.getString(Constants.TYPE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing service type")
        }

        options = JsonSerializer.Options()
        guard let endpoint = try serializer.getString(Constants.SERVICE_ENDPOINT, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing service endpoint")
        }

        // custom properties
        node.remove(Constants.ID)
        node.remove(Constants.TYPE)
        node.remove(Constants.SERVICE_ENDPOINT)
        if node.count > 0 {
            return Service(id, type, endpoint, node)
        }
        
        return Service(id, type, endpoint)
    }

    func toJson(_ generator: JsonGenerator, _ ref: DID?, _ normalized: Bool) {
        generator.writeStartObject()
        generator.writeStringField(Constants.ID, IDGetter(getId()!, ref).value(normalized))
        generator.writeStringField(Constants.TYPE, getType()!)
        generator.writeStringField(Constants.SERVICE_ENDPOINT, endpoint)
        if _properties.count > 0 {
            generatorProperties(generator, _properties, true)
        }
        generator.writeEndObject()
    }
    
    private func generatorJson(_ generator: JsonGenerator, _ node: JsonNode) {
        generatorProperties(generator, node, false)
    }
    
    private func generatorProperties(_ generator: JsonGenerator, _ node: JsonNode, _ objectContext: Bool) {
        switch node.getNodeType() {
        case .ARRAY:
            generator.writeStartArray()
            let elems: [JsonNode] = node.asArray()!
            for elem in elems {
                generatorJson(generator, elem)
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
                generatorJson(generator, node.get(forKey: key)!)
            }
            if !objectContext {
                generator.writeEndObject()
            }
            
            break
        case .DATE:
            generator.writeString(DateFormatter.convertToUTCStringFromDate(node.asDate()!))
            
        case .NSNULL:
             generator.writeNSNULL()
            break
            
        case .NIL:
             generator.writeNSNULL()
            break
        default:  break// DATE
            
        }
    }

    override func equalsTo(_ other: DIDObject) -> Bool {
        guard other is Service else {
            return false
        }

        let service = other as! Service
        return super.equalsTo(other) && endpoint == service.endpoint
    }
}

extension Service {
    public static func == (lhs: Service, rhs: Service) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: Service, rhs: Service) -> Bool {
        return !lhs.equalsTo(rhs)
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        return equalsTo(object as! DIDObject)
    }
}

extension Service {
    public func compareTo(_ service: Service) throws -> ComparisonResult {
        return self.id.compareTo(service.id)
    }
}
