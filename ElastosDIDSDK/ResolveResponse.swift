
import Foundation

public class ResolveResponse: ResolveResult {
    private let JSON_RPC_VERSION = "2.0"
    private let ID = "id"
    private let JSON_RPC = "jsonrpc"
    private let RESULT = "result"
    private let ERROR = "error"
    private let ERROR_CODE = "code"
    private let ERROR_MESSAGE = "message"
    private let ERROR_DATA = "data"

    private var _responseId: String
    private var _jsonRpcVersion: String
    private var _result: ResolveResult?
    private var _error: JsonRpcError?

    init(_ responseId: String, _ result: ResolveResult) {
        self._responseId = responseId
        self._jsonRpcVersion = JSON_RPC_VERSION
        self._result = result
    }
    
    init(_ responseId: String, _ code: Int, _ message: String) {
        self._responseId = responseId
        self._jsonRpcVersion = JSON_RPC_VERSION
        self._error = JsonRpcError(code, message)
    }
    
    public var responseId: String {
        return _responseId
    }
    
    public var result: ResolveResult? {
        return _result
    }
    
    public var errorCode: Int? {
        return _error?.code
    }
    
    public var errorMessage: String? {
        return _error?.message
    }
    
    override func sanitize() throws {
        if _jsonRpcVersion != JSON_RPC_VERSION {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Invalid JsonRPC version")
        }
        if _result == nil && _error == nil {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Missing result or error")
        }
        if result != nil {
            do {
                try result?.sanitize()
            } catch {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Invalid result")
            }
        }
    }
}

/// JsonRPC error object.
class JsonRpcError: NSObject {
    private var _code: Int
    private var _message: String
    private var _data: String?
    
    init(_ code: Int, _ message: String) {
        self._code = code
        self._message = message
    }
    
    var code: Int {
        return _code
    }
    
    var message: String {
        return _message
    }
    
    var data: String? {
        return _data
    }
}

