#-*-  coding: utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rims/passwd/ldap/version'

Gem::Specification.new do |spec|
  spec.name          = "rims-passwd-ldap"
  spec.version       = Rims::Passwd::Ldap::VERSION
  spec.authors       = ["TOKI Yoshinori"]
  spec.email         = ["toki@freedom.ne.jp"]
  spec.summary       = %q{RIMS password source plug-in for LDAP authentication.}
  spec.description   = %q{RIMS password source plug-in for LDAP authentication.}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
end

# Local Variables:
# mode: Ruby
# indent-tabs-mode: nil
# End:
