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
  
  pod 'web3swift'
end

target :ElastosDIDSDK do
  platform :ios, '10.10'
  use_frameworks!
  import_pods
  target 'ElastosDIDSDKTests' do
    inherit! :search_paths
    import_pods
  end
end

target :ElastosDIDSDK _macOS do
  platform :ios, '10.10'
  use_frameworks!
  import_pods
  target 'ElastosDIDSDKTests' do
    inherit! :search_paths
    import_pods
  end
end

