#-*-  coding: utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rims/passwd/ldap/version'

Gem::Specification.new do |spec|
  spec.name          = "rims-passwd-ldap"
  spec.version       = RIMS::Password_LDAPSource_VERSION
  spec.authors       = ["TOKI Yoshinori"]
  spec.email         = ["toki@freedom.ne.jp"]
  spec.summary       = %q{RIMS password source plug-in for LDAP authentication}
  spec.description   = <<-'EOF'
    RIMS password source plug-in for LDAP authentication.
    By introducing this plug-in, RIMS IMAP server will be able to
    authenticate users with LDAP.
  EOF
  spec.homepage      = "https://github.com/y10k/rims-passwd-ldap"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "rims", ">= 0.2.0"
  spec.add_runtime_dependency "net-ldap"
  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "test-unit"
end

# Local Variables:
# mode: Ruby
# indent-tabs-mode: nil
# End:
