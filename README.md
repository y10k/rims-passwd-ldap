RIMS::Password::LDAPSource
==========================

RIMS password source plug-in for LDAP authentication.
By introducing this plug-in, RIMS IMAP server will be able to
authenticate users with LDAP.

Installation
------------

Add this line to your application's Gemfile that includes RIMS:

```ruby
gem 'rims-passwd-ldap'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rims-passwd-ldap

Usage
-----

Add these lines to your config.yml of RIMS:

```yaml
load_libraries:
  - rims/passwd/ldap
authentication:
  - plug_in: ldap
    configuration:
      ldap_uri: ldap://localhost:38900          # hostname and port, `ldaps' for tls (not tested)
      base_dn: ou=user,o=science,dc=nodomain    # base distingished name to search a user
      attribute: uid                            # attribute matched to username
      scope: sub                                # search scope from base dn. `base', `one', or `sub'
      filter: (memberOf=cn=physics,ou=group,o=science,dc=nodomain) # search filter
      search_bind_auth:
        method: simple
        username: cn=search,ou=support,o=science,dc=nodomain       # username to search a user
        password: ********                                         # password to search a user
```

Contributing
------------

1. Fork it ( https://github.com/[my-github-username]/rims-passwd-ldap/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
