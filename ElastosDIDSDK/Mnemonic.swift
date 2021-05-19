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
    @objc public static let DID_CHINESE_SIMPLIFIED = "chinese_simplified"
    @objc public static let DID_CHINESE_TRADITIONAL = "chinese_traditional"
    @objc public static let DID_CZECH = "czech"
    @objc public static let DID_ENGLISH = "english"
    @objc public static let DID_FRENCH = "french"
    @objc public static let DID_ITALIAN = "italian"
    @objc public static let DID_JAPANESE = "japanese"
    @objc public static let DID_KOREAN = "korean"
    @objc public static let DID_SPANISH = "spanish"

    /// Gernerate a random mnemonic.
    /// - Parameter language: The language for DID.
    /// support language string: “chinese_simplified”, “chinese_traditional”, “czech”, “english”, “french”, “italian”, “japanese”, “korean”, “spanish”.
    /// - Throws: Language is empty or failure to generate mnemonic will throw error.
    /// - Returns: Random mnemonic.
    @objc
    public static func generate(_ language: String) throws -> String {
        try checkArgument(!language.isEmpty, "language is empty.")

        let result = language.withCString { (clanuage) in
            return HDKey_GenerateMnemonic(clanuage)
        }

        guard let _ = result else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("generate mnemonic failed.")
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
    public static func isValid(_ language: String, _ mnemonic: String) throws -> Bool {
        try checkArgument(!mnemonic.isEmpty, "Invalid mnemonic.")
        try checkArgument(!language.isEmpty, "Invalid password..")

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
    public static func isValid(_ language: String, _ mnemonic: String, error: NSErrorPointer) -> Bool {
        do {
            return try isValid(language, mnemonic)
        }  catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }
    
    /// Get the language name from a mnemonic string.
    /// - Parameter mnemonic: a mnemonic string.
    /// - Throws: a language name
    public static func getLanguage(_ mnemonic: String) throws -> String {
        try checkArgument(!mnemonic.isEmpty, "Invalid menmonic")
        let langs = [Mnemonic.DID_ENGLISH,
                     Mnemonic.DID_SPANISH,
                     Mnemonic.DID_FRENCH,
                     Mnemonic.DID_CZECH,
                     Mnemonic.DID_ITALIAN,
                     Mnemonic.DID_CHINESE_SIMPLIFIED,
                     Mnemonic.DID_CHINESE_TRADITIONAL,
                     Mnemonic.DID_JAPANESE,
                     Mnemonic.DID_KOREAN]

        for lang in langs {
            do {
                if try Mnemonic.isValid(lang, mnemonic) {
                    return lang
                }
                continue
            } catch {
                continue
            }
        }
        throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError("Invalid menmonic")
    }
}
