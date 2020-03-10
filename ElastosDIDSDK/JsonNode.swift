import Foundation

public class JsonNode {
    private var node: Any

    init() {
        self.node = Dictionary<String, Any>()
    }

    init(_ node: Any) {
        if node is Array<Any> {
            let temp: Array = node as! Array<Any>
            var result: Array<JsonNode> = []
            for subNode in temp {
                result.append(JsonNode(subNode))
            }
            self.node = result
        } else if node is Dictionary<String, Any> {
            let temp: Dictionary<String, Any> = node as! Dictionary<String, Any>
            var result: Dictionary<String, JsonNode> = [:]
            for (key, value) in temp {
                result[key] = JsonNode(value)
            }
            self.node = result
        } else {
            self.node = node
        }
    }

    init(_ node: Dictionary<String, Any>) {
        var result: Dictionary<String, JsonNode> = [:]
        for (key, value) in node {
            result[key] = JsonNode(value)
        }
        self.node = result
    }

    var isEmpty: Bool {
        // TODO:
        return false
    }

    var count: Int {
        if self.node is Dictionary<String, Any> {
            let temp: Dictionary<String, Any> = self.node as! Dictionary<String, Any>
            return temp.count
        } else if self.node is Array<Any> {
            let temp: Array<Any> = self.node as! Array<Any>
            return temp.count
        }
        return 0
    }

    public func toString() -> String {
        // TODO:
        return "TODO"
    }

    func deepCopy() -> JsonNode? {
        
        if self.node is Array<JsonNode> {
            let temp: Array = node as! Array<JsonNode>
            var resultArray: Array<JsonNode> = []
            for subNode in temp {
                resultArray.append(subNode.deepCopy()!)
            }
            let result = JsonNode()
            result.node = resultArray
            return result
        } else if node is Dictionary<String, JsonNode> {
            let temp: Dictionary<String, JsonNode> = node as! Dictionary<String, JsonNode>
            var resultDictionary: Dictionary<String, JsonNode> = [:]
            for (key, value) in temp {
                resultDictionary[key] = value.deepCopy()
            }
            let result = JsonNode()
            result.node = resultDictionary
            return result
        } else {
            return JsonNode(self.node)
        }
    }

    func get(forKey key: String) -> JsonNode? {
        guard self.node is Dictionary<String, JsonNode> else {
            return nil
        }
        let temp: Dictionary<String, JsonNode> = self.node as! Dictionary<String, JsonNode>
        return temp[key]
    }
    
    func put(forKey key: String, value: Array<Any>) {

        guard self.node is Dictionary<String, JsonNode> else {
            return
        }
        
        var node: JsonNode = JsonNode(value)
        var temp: Dictionary<String, JsonNode> = self.node as! Dictionary<String, JsonNode>
        temp[key] = node
        self.node = temp
        
    }
    
    func put(forKey key: String, value: Dictionary<String, Any>) {

        guard self.node is Dictionary<String, JsonNode> else {
            return
        }
        
        let node: JsonNode = JsonNode(value)
        var temp: Dictionary<String, JsonNode> = self.node as! Dictionary<String, JsonNode>
        temp[key] = node
    }
    
    func put(forKey key: String, value: String) {
        
        guard self.node is Dictionary<String, JsonNode> else {
            return
        }
        
        let node: JsonNode = JsonNode(value)
        var temp: Dictionary<String, JsonNode> = self.node as! Dictionary<String, JsonNode>
        temp[key] = node
    }

    func put(forKey key: String, value: Bool) {
        // TOD:
    }

    public func asString() -> String? {
        return self.node as? String
    }

    public func asInteger() -> Int? {
        return self.node as? Int
    }

    public func asArray() -> Array<JsonNode>? {
        return self.node as? Array
    }

    public func asDictionary() -> Dictionary<String, JsonNode>? {
        return self.node as? Dictionary<String, JsonNode>
    }
}
