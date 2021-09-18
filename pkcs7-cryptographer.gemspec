# frozen_string_literal: true

require_relative "lib/pkcs7/cryptographer/version"

Gem::Specification.new do |spec|
  spec.name          = "pkcs7-cryptographer"
  spec.version       = PKCS7::Cryptographer::VERSION
  spec.authors       = ["Daniel Munera Sanchez"]
  spec.email         = ["dmunera119@gmail.com"]

  spec.summary       = "PKCS7 Cryptographer"
  spec.description   =
    "Utility to encrypt and decrypt messages using OpenSSL::PKCS7"
  spec.homepage      = "https://github.com/dmuneras/pkcs7-cryptographer"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.4.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/dmuneras/pkcs7-cryptographer"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{\A(?:test|spec|features)/})
    end
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activesupport", ">= 6.1.4.1"

  spec.add_development_dependency "bundler", ">= 2"
  spec.add_development_dependency "pry"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.2"
  spec.add_development_dependency "rubocop", "1.12.0"
  spec.add_development_dependency "rubocop-rake", "0.5.1"
  spec.add_development_dependency "rubocop-rspec", "2.2.0"
  spec.add_development_dependency "timecop", "0.9.4"
end
