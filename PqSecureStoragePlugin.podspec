require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name = 'PqSecureStoragePlugin'
  s.version = package['version']
  s.summary = package['description']
  s.license = package['license'] || 'MIT'
  s.homepage = package['homepage'] || 'https://github.com/jimcase/pq-secure-storage-plugin'
  s.author = package['author'] || 'PQSecureStorage'
  s.source = { :git => 'https://github.com/jimcase/pq-secure-storage-plugin.git', :tag => s.version.to_s }
  s.source_files = 'ios/Sources/**/*.{swift,h,m,c,cc,mm,cpp}'
  # Low floor so any Capacitor app can depend on it. The PQC that needs iOS 26
  # (SecureEnclave.MLDSA / MLKEM) is gated at runtime with @available; on older iOS the
  # AES-at-rest and Keychain secure storage still work and getHardwareCapabilities reports
  # supportsPqc: false. Building still needs the iOS 26 SDK (Xcode 26+).
  s.ios.deployment_target = '15.0'
  s.dependency 'Capacitor'
  s.swift_version = '5.9'
end
