require "bundler/gem_tasks"
require "rake/testtask"
require "rake/clean"
require 'rake/extensiontask'

gemspec = Bundler::GemHelper.gemspec

CLEAN.include [ 'lib/digest/whirlpool.*', 'ext/argon2-wrapper/libargon2-wrapper.*' ]
CLOBBER.include [ 'ext/digest/whirlpool/mkmf.log', 'ext/digest/whirlpool/Makefile' ]

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.warning = true
  t.test_files = FileList['test/**/*_test.rb']
end

Rake::ExtensionTask.new('whirlpool', gemspec) do |ext|
  ext.ext_dir = 'ext/digest/whirlpool'
  ext.lib_dir = 'lib/digest'
end

# Rake::ExtensionTask.new('argon2-wrapper', gemspec) do |ext|
#   ext.ext_dir = 'ext/argon2-wrapper'
#   ext.lib_dir = 'lib/passwordping'
# end

task :default => :test
