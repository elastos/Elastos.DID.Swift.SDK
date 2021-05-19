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

public enum DIDError: Error {
    public enum UncheckedError {
        public enum IllegalArgumentErrors {
            case MalformedDIDError(_ des: String? = nil)
            case MalformedDIDURLError(_ des: String? = nil)
            case DIDObjectAlreadyExistError(_ des: String? = nil)
            case DIDObjectNotExistError(_ des: String? = nil)
            case InvalidKeyError(_ des: String? = nil)
            case NotControllerError(_ des: String? = nil)
            case IllegalUsageError(_ des: String? = nil)
            case InvalidExpires(_ des: String? = nil)
            case NullPointerErroe(_ des: String? = nil)
            case DataParsingError(_ des: String? = nil)
            case IllegalArgumentError(_ des: String? = nil)
            case EncryptToBase64Error(_ des: String? = nil)
        }
        
        public enum IllegalStateError {
            case DIDNotFoundError(_ des: String? = nil)
            case DIDDeactivatedError(_ des: String? = nil)
            case DIDAlreadyExistError(_ des: String? = nil)
            case DIDExpiredError(_ des: String? = nil)
            case DIDNotUpToDateError(_ des: String? = nil)
            case DIDNotGenuineError(_ des: String? = nil)
            case CredentialNotGenuineError(_ des: String? = nil)
            case CredentialExpiredError(_ des: String? = nil)
            case CredentialRevokedError(_ des: String? = nil)
            case CredentialAlreadyExistError(_ des: String? = nil)
            case RootIdentityAlreadyExistError(_ des: String? = nil)
            case NotCustomizedDIDError(_ des: String? = nil)
            case NoEffectiveControllerError(_ des: String? = nil)
            case NotAttachedWithStoreError(_ des: String? = nil)
            case NotPrimitiveDIDError(_ des: String? = nil)
            case AlreadySignedError(_ des: String? = nil)
            case AlreadySealedError(_ des: String? = nil)
            case UnknownInternalError(_ des: String? = nil)
        }
        
        public enum UnsupportedOperationError {
            case DIDObjectHasReferenceError(_ des: String? = nil)
            case CanNotRemoveEffectiveControllerError(_ des: String? = nil)
            case NotCustomizedDIDError(_ des: String? = nil)
        }
    }
    
    public enum CheckedError {
        public enum MnemonicError {
        }
        
        public enum DIDSyntaxError {
            case MalformedDocumentError(_ des: String? = nil)
            case MalformedCredentialError(_ des: String? = nil)
            case MalformedPresentationError(_ des: String? = nil)
            case MalformedExportDataError(_ des: String? = nil)
            case MalformedIDChainRequestError(_ des: String? = nil)
            case MalformedIDChainTransactionError(_ des: String? = nil)
            case MalformedResolveRequestError(_ des: String? = nil)
            case MalformedResolveResponseError(_ des: String? = nil)
            case MalformedResolveResultError(_ des: String? = nil)
            case MalformedTransferTicketError(_ des: String? = nil)
        }
        
        public enum DIDStoreError {
            public enum DIDStorageErrors {
                case DIDStoreVersionMismatchError(_ des: String? = nil)
            }
            case DIDStorageError(_ des: String? = nil)
            case DIDStoreError(_ des: String? = nil)
            case WrongPasswordError(_ des: String? = nil)
            case DIDStoreCryptoError(_ des: String? = nil)
            case MissingDocumentError(_ des: String? = nil)
            case InvalidPublickeyError(_ des: String? = nil)
            case InvalidDIDMetadataError(_ des: String? = nil)
            case ConflictMergeError(_ des: String? = nil)
        }
        
        public enum DIDBackendError {
            public enum DIDResolveErrors {
                case NetworkError(_ des: String? = nil)
            }
            case DIDTransactionError(_ des: String? = nil)
            case DIDResolveError(_ des: String? = nil)
            case UnsupportedOperationError(_ des: String? = nil)
        }
    }
}

// MARK: - Error Descriptions
extension DIDError.UncheckedError.IllegalArgumentErrors: LocalizedError {
        
    public var errorDescription: String? {
        switch self {
        case .MalformedDIDError(let des):
            return des
        case .MalformedDIDURLError(let des):
            return des
        case .DIDObjectAlreadyExistError(let des):
            return des
        case .DIDObjectNotExistError(let des):
            return des
        case .InvalidKeyError(let des):
            return des
        case .NotControllerError(let des):
            return des
        case .IllegalUsageError(let des):
            return des
        case .InvalidExpires(let des):
            return des
        case .NullPointerErroe(let des):
            return des
        case .DataParsingError(let des):
            return des
        case .IllegalArgumentError(let des):
            return des
        case .EncryptToBase64Error(let des):
            return des
        }
    }
}

extension DIDError.UncheckedError.IllegalStateError: LocalizedError {
    
    public var errorDescription: String? {
        switch self {
        case .DIDNotFoundError(let des):
            return des
        case .DIDDeactivatedError(let des):
            return des
        case .DIDAlreadyExistError(let des):
            return des
        case .DIDExpiredError(let des):
            return des
        case .DIDNotUpToDateError(let des):
            return des
        case .DIDNotGenuineError(let des):
            return des
        case .CredentialNotGenuineError(let des):
            return des
        case .CredentialExpiredError(let des):
            return des
        case .CredentialRevokedError(let des):
            return des
        case .CredentialAlreadyExistError(let des):
            return des
        case .RootIdentityAlreadyExistError(let des):
            return des
        case .NotCustomizedDIDError(let des):
            return des
        case .NoEffectiveControllerError(let des):
            return des
        case .NotAttachedWithStoreError(let des):
            return des
        case .NotPrimitiveDIDError(let des):
            return des
        case .AlreadySignedError(let des):
            return des
        case .AlreadySealedError(let des):
            return des
        case .UnknownInternalError(let des):
            return des
        }
    }
}

extension DIDError.UncheckedError.UnsupportedOperationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .DIDObjectHasReferenceError(let des):
            return des
        case .CanNotRemoveEffectiveControllerError(let des):
            return des
        case .NotCustomizedDIDError(let des):
            return des
        }
    }
}

extension DIDError.CheckedError.DIDSyntaxError: LocalizedError {
    
    public var errorDescription: String? {
        switch self {
        case .MalformedDocumentError(let des):
            return des
        case .MalformedCredentialError(let des):
            return des
        case .MalformedPresentationError(let des):
            return des
        case .MalformedExportDataError(let des):
            return des
        case .MalformedIDChainRequestError(let des):
            return des
        case .MalformedIDChainTransactionError(let des):
            return des
        case .MalformedResolveRequestError(let des):
            return des
        case .MalformedResolveResponseError(let des):
            return des
        case .MalformedResolveResultError(let des):
            return des
        case .MalformedTransferTicketError(let des):
            return des
        }
    }
}

extension DIDError.CheckedError.DIDStoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .WrongPasswordError(let des):
            return des
        case .DIDStoreCryptoError(let des):
            return des
        case .ConflictMergeError(let des):
            return des
        case .InvalidDIDMetadataError(let des):
            return des
        case .InvalidPublickeyError(let des):
            return des
        case .MissingDocumentError(let des):
            return des
        case .DIDStoreError(let des):
            return des
        case .DIDStorageError(let des):
            return des
        }
    }
}

extension DIDError.CheckedError.DIDStoreError.DIDStorageErrors: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .DIDStoreVersionMismatchError(let des):
            return des
        }
    }
}

extension DIDError.CheckedError.DIDBackendError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .DIDTransactionError(let des):
            return des
        case .DIDResolveError(let des):
            return des
        case .UnsupportedOperationError(let des):
            return des
        }
    }
}

extension DIDError.CheckedError.DIDBackendError.DIDResolveErrors: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .NetworkError(let des):
            return des
        }
    }
}
