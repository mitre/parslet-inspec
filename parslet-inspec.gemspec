# encoding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'csv2Inspec/version'

Gem::Specification.new do |spec|
  spec.name          = 'csv2Inspec'
  spec.version       = Csv2Inspec::VERSION
  spec.authors       = ['Rony Xavier']
  spec.email         = ['rx294@gmail.com']
  spec.summary       = 'Infrastructure and compliance testing parser and converter'
  spec.description   = 'csv2Inspec takes the a DISA Stig style CSV and generates inspec controls.'
  spec.homepage      = 'https://github.com/aaronlippold/csv2Inspec'
  spec.license       = 'Apache-2.0'

  spec.files = %w{
    README.md LICENSE csv2Inspec.gemspec
    Gemfile .rubocop.yml
  } + Dir.glob(
    '{bin,data,lib}/**/*', File::FNM_DOTMATCH
  ).reject { |f| File.directory?(f) }

  spec.executables   = %w{ csv2inspec }
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.1'

  spec.add_dependency 'csv', '~> 0'
  spec.add_dependency 'nokogiri', '~> 0'
  spec.add_dependency 'thor', '~> 0.19'
  spec.add_dependency 'yaml', '>= 1.8', '< 3.0'
  spec.add_dependency 'pry', '~> 0'
  spec.add_dependency 'word_wrap', '~> 0'
end
