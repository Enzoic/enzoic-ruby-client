# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'passwordping/version'

Gem::Specification.new do |spec|
  spec.name          = "passwordping_legacy"
  spec.version       = PasswordPing::VERSION
  spec.authors       = ["PasswordPing"]
  spec.email         = ["support@passwordping.com"]

  spec.summary       = 'Ruby 1.8.7 library for PasswordPing API'
  spec.description   = 'Ruby 1.8.7 library for PasswordPing API.  Use the passwordping gem instead of this one unless you need support for older versions of Ruby.'
  spec.homepage      = 'https://github.com/passwordping/passwordping-ruby-client/tree/ruby_1.8.7_support'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.files << `find ext`.split

  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.add_dependency 'rdoc', '4.2.2'
  spec.add_dependency 'bcrypt', '~> 3.1', '>= 3.1.11'
  spec.add_dependency 'unix-crypt', '~> 1.3'
  spec.add_dependency 'base64url', '~> 1.0', '>= 1.0.1'
  spec.add_dependency 'json', '1.8.3'

  spec.add_development_dependency "bundler", '~> 1.10', '>= 1.10.5'
  spec.add_development_dependency "rake", '~> 10.4', '>= 10.4.2'
  spec.add_development_dependency "test-unit", '2.5.5'
  spec.add_development_dependency "rake-compiler", '~> 1.0', '>= 1.0.4'
  spec.extensions = ['ext/argon2_import/extconf.rb', 'ext/digest/whirlpool/extconf.rb' ]
end
