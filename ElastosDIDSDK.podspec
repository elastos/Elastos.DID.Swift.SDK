#
#  Be sure to run `pod spec lint hive.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see https://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|

  s.name         = 'ElastosDIDSDK'
  s.version      = '2.0.0'
  s.summary      = 'Elastos Hive iOS SDK Distribution.'
  s.swift_version = '4.2'
  s.description  = 'Elastos hive ios sdk framework distribution.'
  s.homepage     = 'https://www.elastos.org'
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { 'hive-dev' => 'support@elastos.org' }
  s.platform     = :ios, '11.0'
  s.ios.deployment_target = '11.0'
  s.source = {:git => 'https://github.com/elastos/Elastos.DID.Swift.SDK.git', :tag => s.version}
  s.source_files = 'ElastosDIDSDK/**/*.{h,m,swift}','Externals/Antlr4/**/**/*.{h,m,swift,interp,tokens,g4}','Externals/base58/*.{swift}','Externals/ByteBuffer/*.{swift}','Externals/CryptorECC/*.{swift}','Externals/HDKey/include/*.{h,swift}','Externals/SwiftJWT/*.{swift}'
  s.vendored_libraries = 'Externals/HDKey/lib/*.a'
  s.dependency 'PromiseKit','~> 6.9'
  s.dependency 'BlueRSA', '~> 1.0'
  s.dependency 'LoggerAPI','~> 1.7'
  s.dependency 'KituraContracts','~> 1.1'
  s.dependency 'BlueCryptor', '~> 1.0'
  s.dependency 'ReadWriteLock', '~> 1.0'
  s.dependency 'Swifter'

  s.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
end
