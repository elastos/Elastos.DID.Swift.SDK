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

/// Base class that defines public API for writing JSON content.
/// Instances are created using factory methods of JsonFactory instance.
@objc(JsonGenerator)
public class JsonGenerator: NSObject {
    private static let COLON: Character = ":"
    private static let COMMA: Character = ","
    private static let OBJECT_STARTED: Character = "{"
    private static let OBJECT_END: Character = "}"
    private static let ARRAY_STARTED: Character = "["
    private static let ARRAY_END: Character = "]"
    private static let STRING_QUOTE_STARTED: Character = "\""
    private static let STRING_QUOTE_END: Character = "\""

    private var position: Int
    private var deep: Int
    private var state: [UInt8]
    private var buffer: String

    enum State: UInt8 {
        case Unkown = 0
        case Root = 1
        case Object = 2
        case Array = 3
        case Field = 4

        static func valueOf(_ value: UInt8) -> State {
            let state: State

            switch value {
            case 0:
                state = .Unkown
            case 1:
                state = .Root
            case 2:
                state = .Object
            case 3:
                state = .Array
            case 4:
                state = .Field
            default:
                state = .Unkown
            }
            return state
        }
    }

    @objc
    public override init() {
        self.position = 0
        self.deep = 0
        self.buffer = ""
        self.state = []
    }

    private func pushState(_ state: State) {
        // TODO: CHECK
        if self.deep > self.state.count - 1 {
            self.state.append(state.rawValue)
        } else {
            self.state[self.deep] = state.rawValue
        }
        deep += 1
    }

    private func popState() -> State {
        if deep <= 0 {
            return .Unkown
        }

        deep -= 1
        return State.valueOf(state[deep] & 0x7F)
    }

    private func getState() -> State {
        if deep <= 0 {
            return .Unkown
        }

        return State.valueOf(state[deep-1] & 0x7F)
    }

    private func setSticky() {
        if deep - 1 < 0 {
            return
        }
        
        if deep - 1 > self.state.count {
            state.append(0)
        }
        state[deep - 1] |= 0x80
    }

    private func isSticky() -> Bool {
        if deep <= 0 {
            return false
        }

        return state[deep-1] & 0x80 == 0x80
    }

    /// Method for writing starting marker of an Object value.
    @objc
    public func writeStartObject() {
        if isSticky() {
            buffer.append(JsonGenerator.COMMA)
        }

        buffer.append(JsonGenerator.OBJECT_STARTED)
        setSticky()
        pushState(.Object)
    }

    /// Method for writing closing marker of an Object value.
    @objc
    public func writeEndObject() {
        buffer.append(JsonGenerator.OBJECT_END)
        _ = popState()
        if getState() == .Field {
            _ = popState() /* Pop field state*/
        }
    }

    /// Method for writing starting marker of a Array value.
    @objc
    public func writeStartArray() {
        buffer.append(JsonGenerator.ARRAY_STARTED)
        pushState(.Array)
    }

    /// Method for writing closing marker of a JSON Array value.
    @objc
    public func writeEndArray() {
        buffer.append(JsonGenerator.ARRAY_END)
        _ = popState()
        if getState() == .Field {
            _ = popState() /* pop field state */
        }
    }

    /// Method for writing a field name .
    /// - Parameter name: Field names
    @objc
    public func writeFieldName(_ name: String) {
        if isSticky() {
            buffer.append(JsonGenerator.COMMA)
        }

        buffer.append(JsonGenerator.STRING_QUOTE_STARTED)
        buffer.append(name)
        buffer.append(JsonGenerator.STRING_QUOTE_END)
        buffer.append(JsonGenerator.COLON)

        setSticky()
        pushState(.Field)
    }

    /// Public API, write methods, binary/raw content.
    /// Method that will force generator to copy input text verbatim without any modifications.
    /// - Parameter value: String value to write
    @objc
    public func writeRawValue(_ value: String) {
        if isSticky() {
            buffer.append(JsonGenerator.COMMA)
        }

        buffer.append(value)

        if getState() == .Field {
            _ = popState()
        } else {
            setSticky()
        }
    }

    ///  Public API, write methods, text/String values.
    ///  Method for outputting a String value.
    /// - Parameter value: String value to write
    @objc
    public func writeString(_ value: String) {
        if isSticky() {
            buffer.append(JsonGenerator.COMMA)
        }

        if !value.isEmpty {
            buffer.append(JsonGenerator.STRING_QUOTE_STARTED)
            buffer.append(value)
            buffer.append(JsonGenerator.STRING_QUOTE_END)
        } else {
            buffer.append(JsonGenerator.STRING_QUOTE_STARTED)
            buffer.append(JsonGenerator.STRING_QUOTE_END)
        }

        if getState() == .Field {
            _ = popState()
        } else {
            setSticky()
        }
    }

    /// Public API, write methods, numeric.
    /// Method for outputting given value as JSON number.
    /// - Parameter value: Number value to write
    @objc
    public func writeNumber(_ value: Any) {
        if isSticky() {
            buffer.append(JsonGenerator.COMMA)
        }

        buffer.append("\(value)")

        if getState() == .Field {
            _ = popState()
        } else {
            setSticky()
        }
    }

    /// Public API, write methods, other value types.
    /// Method for outputting literal JSON boolean value (one of Strings 'true' and 'false').
    /// - Parameter value: Bool value to write
    @objc
    public func writeBool(_ value: Bool) {
        if isSticky() {
            buffer.append(JsonGenerator.COMMA)
        }

        if value {
            buffer.append("true")
        } else {
            buffer.append("false")
        }

        if getState() == .Field {
            _ = popState()
        } else {
            setSticky()
        }
    }

    /// Convenience method for outputting a field entry ("member")
    /// that has a String value. Equivalent to:
    /// <pre>
    /// writeFieldName(fieldName)
    /// writeString(value)
    /// </pre>
    /// <p>
    /// Note: many performance-sensitive implementations override this method
    /// - Parameters:
    ///   - name: Field names
    ///   - value: String value to write
    @objc
    public func writeStringField(_ name: String, _ value: String) {
        writeFieldName(name)
        writeString(value)
    }

    /// Convenience method for outputting a field entry ("member")
    /// that has the specified numeric value. Equivalent to:
    /// <pre>
    /// writeFieldName(fieldName)
    /// writeNumber(value)
    /// </pre>
    /// - Parameters:
    ///   - name: Field names
    ///   - value: Int value to write
    @objc
    public func writeNumberField(_ name: String, _ value: Int) {
        writeFieldName(name)
        writeNumber(value)
    }

    /// Convenience method for outputting a field entry ("member")
    /// that has the specified bool value. Equivalent to:
    /// <pre>
    /// writeFieldName(fieldName)
    /// writeBool(value)
    /// </pre>
    /// - Parameters:
    ///   - name: Field names
    ///   - value: Bool value to write
    @objc
    public func writeBoolField(_ name: String, _ value: Bool) {
        writeFieldName(name)
        writeBool(value)
    }

    /// JsonGenerator converted to json string
    /// - Returns: String value
    @objc
    public func toString() -> String {
        let output = buffer
        buffer = ""
        return output
    }
}
