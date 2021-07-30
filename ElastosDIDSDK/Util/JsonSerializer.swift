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

class JsonSerializer {
    private var node: JsonNode

    init(_ data: JsonNode) {
        self.node = data
    }

    func getString(_ keyName: String, _ options: Options) throws -> String? {
        let child = node.get(forKey: keyName)

        guard let _ = child else {
            if options.optional {
                return options.refValue! as? String
            } else {
                return nil
            }
        }

        let value = child!.asString()
        guard !(value?.isEmpty ?? false) else {
            return nil
        }
        return value ?? ""
    }

    func getInteger(_ keyName: String, _ options: Options) throws -> Int? {
        let child = node.get(forKey: keyName)

        guard let _ = child else {
            if options.optional {
                return options.refValue as? Int
            } else {
                return nil
            }
        }

        let value = child!.asInteger()
        guard let _ = value else {
            return nil
        }
        return value!
    }

    func getDID(_ keyName: String, _ options: Options) throws -> DID? {
        let child = node.get(forKey: keyName)

        guard let _ = child else {
            if options.optional {
                if options.refValue == nil {
                    return nil
                }
                return options.refValue as? DID
            } else {
                return nil
            }
        }

        let value = child!.asString()
        guard !(value?.isEmpty ?? false) else {
            return nil
        }

        let did: DID
        do {
            did = try DID(value!)
        } catch {
            return nil
        }
        return did
    }

    func getDIDURL(_ keyName: String, _ options: Options) throws -> DIDURL? {
        let child = node.get(forKey: keyName)

        guard let _ = child else {
            if options.optional {
                return nil
            } else {
                return nil
            }
        }

        let value = child!.asString()
        guard !(value?.isEmpty ?? false) else {
            return nil
        }

        let id: DIDURL
        do {
            let ref: DID? = options.refValue as? DID
            if ref != nil && value!.hasPrefix("#") {
                let fragment = String(value!.suffix(value!.count - 1))
                id = try DIDURL(ref!, "#" + fragment)
            } else {
                id = try DIDURL(value!)
            }
        } catch {
            return nil
        }
        return id
    }

    func getDIDURL(_ options: Options) throws -> DIDURL? {
        let value = node.asString()

        guard let _ = value else {
            if options.optional {
                return nil
            } else {
                return nil
            }
        }

        guard !(value!.isEmpty) else {
            return nil
        }

        let id: DIDURL
        do {
            let ref: DID? = options.refValue as? DID
            if ref != nil && value!.hasPrefix("#") {
                let fragment = String(value!.suffix(value!.count - 1))
                id = try DIDURL(ref!, fragment)
            } else {
                id = try DIDURL(value!)
            }
        } catch {
            return nil
        }
        return id
    }

    func getDate(_ keyName: String, _ options: Options) throws -> Date? {
        let child = node.get(forKey: keyName)

        guard let _ = child else {
            if options.optional {
                return options.refValue! as? Date
            } else {
                return nil
            }
        }

        let value = child!.asString()
        guard !(value?.isEmpty ?? false) else {
            return nil
        }

        let date = DateFormatter.convertToUTCDateFromString(value!)
        guard let _ = date else {
            return nil
        }

        return date!
    }

    class Options {
        var optional: Bool
        var refValue: Any?
        var hint: String
        
        init() {
            self.optional = false
            self.hint = ""
        }

        func withOptional() -> Options {
            self.optional = true
            return self
        }

        func withOptional(_ optional: Bool) -> Options {
            return optional ? withOptional() : self
        }

        func withRef(_ ref: Any?) -> Options {
            self.refValue = ref
            return self
        }
    }
}
