#
#  Be sure to run `pod spec lint hive.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see https://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|

  s.name         = "ElastosDIDSDK"
  s.version      = "1.0.0"
  s.summary      = "Elastos DID iOS SDK Distribution."
  s.swift_version = '4.2'
  s.description  = 'Elastos did ios sdk framework distribution.'
  s.homepage     = "https://www.elastos.org"
  s.license      = { :type => "MIT", :file => "ElastosDIDSDK-framework/LICENSE" }
  s.author       = { "did-dev" => "release@elastos.org" }
  s.platform     = :ios, "11.0"
  s.ios.deployment_target = "11.0"
  s.source       = {'http':'https://github.com/elastos/Elastos.NET.DID.Swift.SDK/releases/download/release-v1.0.1/ElastosDIDSDK-framework.zip'}
  s.vendored_frameworks = 'ElastosDIDSDK-framework/*.framework'
  s.source_files = 'ElastosDIDSDK-framework/ElastosDIDSDK.framework/**/*.h'


end
