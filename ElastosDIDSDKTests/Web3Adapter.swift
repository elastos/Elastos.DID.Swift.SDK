
import Foundation
@testable import ElastosDIDSDK
import web3swift
import BigInt

struct Wallet {
    let address: String
    let data: Data
    let name: String
    let isHD: Bool
}

class Web3Adapter: DefaultDIDAdapter {
    var web33: web3
    var walletAddress: EthereumAddress
    let password: String
//    let endpoint = "http://52.80.107.251:1111"
    let endpoint: String
    let contractAddress: String
    let contractMethod = "publishDidTransaction"
    var lastTxHash: String = ""

    public init(_ rpcEndpoint: String = "http://52.80.107.251:1111", _ contractAddress: String = "0xEA2256bd30cfeC643203d1a6f36A90A4fD17863E", _ walletFile: String, _ walletPassword: String = "password") {
        let dic = ["address": "d0a6217213d86c3a86814522f287ad2004edf579",
                   "id": "b8830f72-3671-4dd6-af4d-aa2b821a6890",
                   "version": 3,
                   "crypto": ["cipher": "aes-128-ctr",
                              "ciphertext": "1746ef5c50a2561c763255b27627c3bd9a94c0193843264f979635570e3aa3a3",
                              "cipherparams": ["iv": "ba4436d41b8e98a7e17b8c751f6e2437"],
                              "kdf": "scrypt",
                              "kdfparams": ["dklen": 32,
                                            "n": 262144,
                                            "p": 1,
                                            "r": 8,
                                            "salt": "e3d2fa7bce5ab54d95153bdaf653fb409404c4d1b14e9d119a77a4b3b060d19e"],
                              "mac": "30591564bcb7fab0125b45ab10cb404a1e31d068156f947303dadd3c573fece9"]] as [String : Any]
        self.contractAddress = contractAddress
        self.password = walletPassword
        self.endpoint = rpcEndpoint
        let keystore = EthereumKeystoreV3(dic.toJsonString()!)
        let keyData = try! JSONEncoder().encode(keystore!.keystoreParams)
        let address = keystore?.addresses!.first!.address
        let wallet = Wallet(address: address!, data: keyData, name: "rpcTestName", isHD: false)

        let data = wallet.data
        let keystoreManager: KeystoreManager
        if wallet.isHD {
            let keystore = BIP32Keystore(data)!
            keystoreManager = KeystoreManager([keystore])
        } else {
            let keystore = EthereumKeystoreV3(data)!
            keystoreManager = KeystoreManager([keystore])
        }
        
        let ethereumAddress = EthereumAddress(wallet.address)!
        _ = try! keystoreManager.UNSAFE_getPrivateKeyData(password: password, account: ethereumAddress).toHexString()

        self.web33 = web3(provider: Web3HttpProvider(URL(string: endpoint)!, network: Networks.Mainnet)!)
        web33.addKeystoreManager(keystoreManager)
        self.walletAddress = EthereumAddress(wallet.address)! // Address which balance we want to know
        let balanceResult = try! web33.eth.getBalance(address: walletAddress)
        let balanceString = Web3Utils.formatToEthereumUnits(balanceResult, toUnits: .eth, decimals: 3)
        print("================================================")
        print("Wallet address: \(walletAddress.address)")
        print("Wallet balance: \(String(describing: balanceString))")
        print("================================================")
        super.init(rpcEndpoint)
    }
    
    override func createIdTransaction(_ payload: String, _ memo: String?) throws {
        let value: String = "1.0" // Any amount of Ether you need to send
        let contractABIParam = [["inputs": [], "stateMutability": "nonpayable", "payable": false, "type": "constructor"],["inputs": [["internalType": "name", "type": "string"]], "name": "publishDidTransaction", "outputs": [], "stateMutability": "nonpayable", "payable": false, "type": "function"]] as [[String: Any]]
        let contractABI = contractABIParam.toJsonString()
        let contractAddress = EthereumAddress(self.contractAddress)!
        let abiVersion = 2 // Contract ABI version
        let extraData: Data = Data() // Extra data for contract method
        _ = Web3Utils.parseToBigUInt(value, units: .eth)
        let parameters: [AnyObject] = [payload] as [AnyObject]// Parameters for contract method
//        let price = try web33.eth.getGasPrice()
        var options = TransactionOptions.defaultOptions
        options.value = 0
        options.from = walletAddress
        options.gasPrice = .manual(3000000000000)
        options.gasLimit = .limited(1000000)
        web33.transactionOptions = options
        let contract = web33.contract(contractABI!, at: contractAddress, abiVersion: abiVersion)!
//            web3contract(web3: web33, abiString: contractABI!, at: contractAddress, transactionOptions: options, abiVersion: abiVersion)!
//        web33.contract(contractABI!, at: contractAddress, abiVersion: abiVersion)!
        let tx = contract.write(
            contractMethod,
            parameters: parameters,
            extraData: extraData,
            transactionOptions: options)!
        tx.transactionOptions.from = walletAddress
        tx.transactionOptions.value = 0
        
        do {
            let transactionSendingResult = try tx.send(password: password, transactionOptions: options)
            self.lastTxHash = transactionSendingResult.hash
            print(transactionSendingResult.transaction)
            print(transactionSendingResult.hash)

        } catch {
            print(error)
        }
    }

    func isAvailable() -> Bool {

        if self.lastTxHash.count == 0 {
            return true
        }

        let tx = try! web33.eth.getTransactionDetails(self.lastTxHash)
        //TODO:
        print(tx.transaction.txhash as Any)
        print(tx.transaction.inferedChainID as Any)
        return tx.transaction.txhash == self.lastTxHash
    }
}
