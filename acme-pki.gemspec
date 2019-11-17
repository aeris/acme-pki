lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'acme/pki/version'

Gem::Specification.new do |spec|
	spec.name = 'acme-pki'
	spec.version = Acme::PKI::VERSION
	spec.authors = ['Aeris']
	spec.email = ['aeris@imirhil.fr']
	spec.summary = %q{Ruby client for Let's Encrypt}
	spec.description = %q{Manage your keys, requests and certificates.}
	spec.homepage = 'https://github.com/aeris/acme-pki/'
	spec.license = 'AGPL-3.0+'

	spec.files = `git ls-files -z`.split("\x0")
	spec.executables = spec.files.grep(%r{^bin/}) { |f| File.basename f }
	spec.test_files = spec.files.grep %r{^(test|spec|features)/}
	spec.require_paths = %w(lib)

	spec.add_development_dependency 'bundler', '~> 2.0.2'
	spec.add_development_dependency 'awesome_print', '~> 1.8.0'
	spec.add_development_dependency 'pry-byebug', '~> 3.7.0'

	spec.add_dependency 'acme-client', '~> 2.0.5'
	spec.add_dependency 'faraday_middleware', '~> 0.13.1'
	spec.add_dependency 'colorize', '~> 0.8.1'
	spec.add_dependency 'simpleidn', '~> 0.1.1'
end
