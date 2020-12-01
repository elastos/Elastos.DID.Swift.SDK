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

@objc(Mnemonic)
public class Mnemonic: NSObject {
    @objc public static let CHINESE_SIMPLIFIED = "chinese_simplified"
    @objc public static let CHINESE_TRADITIONAL = "chinese_traditional";
    @objc public static let CZECH = "Czech";
    @objc public static let ENGLISH = "english";
    @objc public static let FRENCH = "French";
    @objc public static let ITALIAN = "Italian";
    @objc public static let JAPANESE = "japanese";
    @objc public static let KOREAN = "Korean";
    @objc public static let SPANISH = "Spanish";

    /// Gernerate a random mnemonic.
    /// - Parameter language: The language for DID.
    /// support language string: “chinese_simplified”, “chinese_traditional”, “czech”, “english”, “french”, “italian”, “japanese”, “korean”, “spanish”.
    /// - Throws: Language is empty or failure to generate mnemonic will throw error.
    /// - Returns: Random mnemonic.
    @objc
    public class func generate(_ language: String) throws -> String {
        guard !language.isEmpty else {
            throw DIDError.illegalArgument("language is empty.")
        }

        let result = language.withCString { (clanuage) in
            return HDKey_GenerateMnemonic(clanuage)
        }

        guard let _ = result else {
            throw DIDError.illegalArgument("generate mnemonic failed.")
        }

        return String(cString: result!)
    }
    
    /// Check mnemonic.
    /// - Parameters:
    ///   - language: The language for DID.
    ///   support language string: “chinese_simplified”, “chinese_traditional”, “czech”, “english”, “french”, “italian”, “japanese”, “korean”, “spanish”.
    ///   - mnemonic: mnemonic string.
    /// - Throws: mnemonic or language is empty.
    /// - Returns: true, if mnemonic is valid. or else, return false.
    public class func isValid(_ language: String, _ mnemonic: String) throws -> Bool {
        guard !mnemonic.isEmpty else {
            throw DIDError.illegalArgument("Invalid mnemonic.")
        }

        guard !language.isEmpty else {
            throw DIDError.illegalArgument("Invalid password..")
        }

        return language.withCString { (clang) in
            return mnemonic.withCString { (cmnemonic) in
                return HDKey_MnemonicIsValid(cmnemonic, clang)
            }
        }
    }

    /// Check mnemonic.
    /// - Parameters:
    ///   - language: The language for DID.
    ///   support language string: “chinese_simplified”, “chinese_traditional”, “czech”, “english”, “french”, “italian”, “japanese”, “korean”, “spanish”.
    ///   - mnemonic: mnemonic string.
    /// - Throws: mnemonic or language is empty.
    /// - Returns: true, if mnemonic is valid. or else, return false.
    @objc
    public class func isValid(_ language: String, _ mnemonic: String, error: NSErrorPointer) -> Bool {
        do {
            return try isValid(language, mnemonic)
        }  catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }
}
