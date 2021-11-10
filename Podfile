def import_pods
  pod 'PromiseKit', '~> 6.8'
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

workspace 'ElastosDIDSDK.xcworkspace'
xcodeproj 'ElastosDIDSDK.xcodeproj' 
xcodeproj 'DIDExample/DIDExample.xcodeproj'

target :ElastosDIDSDK do
xcodeproj 'ElastosDIDSDK' 
  platform :ios, '11.0'
  use_frameworks!
  import_pods
  target 'ElastosDIDSDKTests' do
    inherit! :search_paths
    import_pods
    pod 'web3swift', '~> 2.3.0'

  end
end

target :"DIDExample" do
xcodeproj 'DIDExample/DIDExample'
    source 'https://github.com/CocoaPods/Specs.git'
    platform :ios, '11.0'
    use_frameworks!
    import_pods
    pod 'WMPageController'
    pod 'SnapKit', '~> 4.0.0'
end