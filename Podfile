def import_pods
  pod 'PromiseKit'
  pod 'BlueRSA', '~> 1.0'
  pod 'LoggerAPI', '~> 1.7'
  pod 'KituraContracts', '~> 1.1'
  pod 'BlueCryptor', '~> 1.0'
  pod 'ReadWriteLock', '~> 1.0'
  pod 'Swifter'
  pod 'Alamofire'
  pod 'Telegraph'
  pod 'SSZipArchive'
 # pod 'CryptoSwift', '~> 1.4.1'

end

target :ElastosDIDSDK do
  platform :ios, '10.10'
  use_frameworks!
  import_pods
  target 'ElastosDIDSDKTests' do
    inherit! :search_paths
    import_pods
    pod 'web3swift', '~> 2.3.0'

  end
end

target :ElastosDIDSDK_macOS do
    platform :osx, '10.15'
    use_frameworks!
    import_pods
end



