
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

//    public init(_ rpcEndpoint: String = "http://52.80.107.251:1111", _ contractAddress: String = "0xEA2256bd30cfeC643203d1a6f36A90A4fD17863E", _ walletFile: String, _ walletPassword: String = "password") {
    public init(_ rpcEndpoint: String, _ contractAddress: String, _ walletFile: String, _ walletPassword: String) {
        let walletData = FileManager.default.contents(atPath: walletFile)
        self.contractAddress = contractAddress
        self.password = walletPassword
        self.endpoint = rpcEndpoint
        let keystore = EthereumKeystoreV3(String(data: walletData!, encoding: .utf8)!)
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

//        self.web33 = web3(provider: Web3HttpProvider(URL(string: endpoint)!, network: Networks.Custom(networkID: 23))!)
        self.web33 = web3(provider: Web3HttpProvider(URL(string: endpoint)!, network: Networks.Custom(networkID: 23))!)

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
        options.gasPrice = .manual(1000000000000) // 12
        options.gasLimit = .limited(8000000) // 6
//        options.nonce = .manual(0)
        web33.transactionOptions = options
        let contract = web33.contract(contractABI!, at: contractAddress, abiVersion: abiVersion)!
        let tx = contract.write(
            contractMethod,
            parameters: parameters,
            extraData: extraData,
            transactionOptions: options)!
        tx.transactionOptions.from = walletAddress
        tx.transactionOptions.value = 0
//        tx.transaction.UNSAFE_setChainID(23)
        do {
            let transactionSendingResult = try tx.send(password: password, transactionOptions: options)
            self.lastTxHash = transactionSendingResult.hash
            print(transactionSendingResult.transaction)
            print(transactionSendingResult.hash)
            let detial = try web33.eth.getTransactionDetails(self.lastTxHash)
            print("detial.blockNumber == \(detial.blockNumber)")
        } catch {
            print("error == \(error)")
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
