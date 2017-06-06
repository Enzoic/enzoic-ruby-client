# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'passwordping/version'

Gem::Specification.new do |spec|
  spec.name          = "passwordping"
  spec.version       = PasswordPing::VERSION
  spec.authors       = ["PasswordPing"]
  spec.email         = ["support@passwordping.com"]

  spec.summary       = 'Ruby library for PasswordPing API'
  spec.description   = 'Ruby library for PasswordPing API'
  spec.homepage      = 'https://github.com/passwordping/passwordping-ruby-client'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.files << `find ext`.split

  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.add_dependency 'ffi', '~> 1.9'
  spec.add_dependency 'ffi-compiler', '~> 0.1'
  spec.add_dependency 'rest-client', '~> 2.0', '>= 2.0.2'
  spec.add_dependency 'bcrypt', '~> 3.1', '>= 3.1.11'
  spec.add_dependency 'unix-crypt', '~> 1.3'

  spec.add_development_dependency "bundler", '~> 1.10', '>= 1.10.5'
  spec.add_development_dependency "rake", '~> 10.4', '>= 10.4.2'
  spec.add_development_dependency "test-unit", '~> 3.2', '>= 3.2.4'
  spec.add_development_dependency "rake-compiler", '~> 1.0', '>= 1.0.4'
  spec.extensions = ['ext/argon2-wrapper/extconf.rb', "ext/digest/whirlpool/extconf.rb" ]
end
