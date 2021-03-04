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
        public enum IllegalArgumentError {
            case MalformedDIDError(_ des: String?)
            case MalformedDIDURLError(_ des: String?)
            case DIDObjectAlreadyExistError(_ des: String?)
            case DIDObjectNotExistError(_ des: String?)
            case InvalidKeyError(_ des: String?)
            case NotControllerError(_ des: String?)
            case IllegalUsageError(_ des: String?)
        }
        
        public enum IllegalStateError {
            case DIDNotFoundError(_ des: String?)
            case DIDDeactivatedError(_ des: String?)
            case DIDAlreadyExistError(_ des: String?)
            case DIDExpiredError(_ des: String?)
            case DIDNotUpToDateError(_ des: String?)
            case DIDNotGenuineError(_ des: String?)
            case CredentialNotGenuineError(_ des: String?)
            case CredentialExpiredError(_ des: String?)
            case CredentialRevokedError(_ des: String?)
            case CredentialAlreadyExistError(_ des: String?)
            case RootIdentityAlreadyExistError(_ des: String?)
            case NotCustomizedDIDError(_ des: String)
            case NoEffectiveControllerError(_ des: String?)
            case NotAttachedWithStoreError(_ des: String?)
            case NotPrimitiveDIDError(_ des: String?)
            case AlreadySignedError(_ des: String?)
            case AlreadySealedError(_ des: String?)
            case UnknownInternalError(_ des: String?)
        }
        
        public enum UnsupportedOperationError {
            case DIDObjectHasReferenceError(_ des: String?)
            case CanNotRemoveEffectiveControllerError(_ des: String?)
        }
    }
    
    public enum CheckedError {
        public enum MnemonicError {
        }
        
        public enum DIDSyntaxError {
            case MalformedDocumentError(_ des: String?)
            case MalformedCredentialError(_ des: String)
            case MalformedPresentationError(_ des: String?)
            case MalformedExportDataError(_ des: String?)
            case MalformedIDChainRequestError(_ des: String?)
            case MalformedIDChainTransactionError(_ des: String?)
            case MalformedResolveRequestError(_ des: String?)
            case MalformedResolveResponseError(_ des: String?)
            case MalformedResolveResultError(_ des: String?)
            case MalformedTransferTicketError(_ des: String?)
        }
        
        public enum DIDStoreError {
            public enum DIDStorageError {
                case DIDStoreVersionMismatchError(_ des: String?)
            }
            case WrongPasswordError(_ des: String?)
            case DIDStoreCryptoError(_ des: String?)
        }
        
        public enum DIDBackendError {
            public enum DIDResolveError {
                case NetworkError(_ des: String?)
            }
            case DIDTransactionError(_ des: String?)
        }
    }
}

// MARK: - Error Descriptions
extension DIDError.UncheckedError.IllegalArgumentError: LocalizedError {
        
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
        }
    }
}

extension DIDError.CheckedError.DIDStoreError.DIDStorageError: LocalizedError {
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
        }
    }
}

extension DIDError.CheckedError.DIDBackendError.DIDResolveError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .NetworkError(let des):
            return des
        }
    }
}

/*
extension DIDError {
    static func desription(_ error: DIDError) -> String {
        switch error {
        case .unknownFailure(let des):
            return des ?? "unknown failure"
        case .illegalArgument(let des):
            return des ?? "invalid arguments"

        case .malformedMeta(let des):
            return des ?? "malformed metadata"
        case .malformedDID(let des):
            return des ?? "malformed DID string"
        case .malformedDIDURL(let des):
            return des ?? "malformed DIDURL string"
        case .malformedDocument(let des):
            return des ?? "malformed DID document"
        case .malformedCredential(let des):
            return des ?? "malformed credential"
        case .malformedPresentation(let des):
            return des ?? "malformed presentation"

        case .didStoreError(let des):
            return des ?? "unknown didstore error"

        case .didResolveError(let des):
            return des ?? "did resolve failure"
        case .didDeactivated(let des):
            return des ?? "did was deactivated"
        case .didExpired(let des):
            return des ?? "did was expired"

        case .didtransactionError(let des):
            return des ?? "did transaction failure"

        case .invalidState(let des):
            return des ?? "invalid wrong state"

        case .notFoundError(let des):
            return des ?? "not found"
        case .didNotFoundError(let des):
            return des ?? "did not found"
        case .invalidKeyError(let des):
            return des ?? "invalid key"
        case .didMetaDateLocalFormatError(let des):
            return des ?? "Loading metadata format error."
        case .didNotUpToDate(let des):
            return des ?? "DID document not up-to-date."
        case .didNotGenuine(let des):
            return des ?? "Publish failed because document is not genuine."
        case .IllegalArgumentError(let des):
            return des ?? "invalid arguments"
        }
    }
}
*/
