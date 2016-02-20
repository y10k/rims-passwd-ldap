# -*- coding: utf-8 -*-

require 'logger'
require 'net/ldap'
require 'pp' if $DEBUG
require 'rims/passwd/ldap'
require 'test/unit'
require 'uri'
require 'yaml'

module RIMS::Password::LDAPSource::Test
  module LDAPExample
    AUTH = YAML.load_file(File.join(File.dirname(__FILE__), '..', 'docker', 'build', 'auth.yml'))
    PORT = AUTH['port']
    USERS = YAML.load_file(File.join(File.dirname(__FILE__), '..', 'docker', 'users.yml'))
    SEARCH = USERS['support'].find{|role| role['cn'] == 'search' }
    SEARCH_USER = "cn=#{SEARCH['cn']},ou=support,o=science,dc=nodomain"
    SEARCH_PASS = SEARCH['userPassword']
  end

  module LDAPSourceTestMethod
    include LDAPExample

    def setup
      @logger = Logger.new(STDOUT)
      @logger.level = ($DEBUG) ? Logger::DEBUG : Logger::FATAL
      @search_bind_verification_skip = false
      @search_bind_auth = {
        method: :simple,
        username: SEARCH_USER,
        password: SEARCH_PASS
      }
    end

    def open_ldap_src(ldap_uri, search_bind_auth: @search_bind_auth)
      ldap_uri = URI.parse(ldap_uri)

      host = ldap_uri.host
      port = ldap_uri.port
      base_dn = ldap_uri.dn
      attr = ldap_uri.attributes

      optional = {}
      optional[:scope] = ldap_uri.scope if ldap_uri.scope
      optional[:filter] = ldap_uri.filter if ldap_uri.filter
      optional[:search_bind_auth] = search_bind_auth if search_bind_auth
      optional[:search_bind_verification_skip] = @search_bind_verification_skip
      case (ldap_uri.scheme)
      when 'ldap'
        # ok
      when 'ldaps'
        optional[:encryption] = true
      else
        raise "unknown URI scheme: #{ldap_uri}"
      end

      ldap_src = RIMS::Password::LDAPSource.new(host, port, base_dn, attr, **optional)
      ldap_src.logger = @logger

      ldap_src.start
      begin
        yield(ldap_src)
      ensure
        ldap_src.stop
      end
    end
    private :open_ldap_src

    def test_raw_password?
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid") {|ldap_src|
        assert_false(ldap_src.raw_password?)
      }
    end

    def test_users
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_wrong_password
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_false(ldap_src.compare_password(user['uid'], 'invalid_pass'), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_wrong_base_dn
      open_ldap_src("ldap://localhost:#{PORT}/o=science,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      open_ldap_src("ldap://localhost:#{PORT}/o=no_org,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_scope_base
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid?base") {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      for user in USERS['user']
        open_ldap_src("ldap://localhost:#{PORT}/uid=#{user['uid']},ou=user,o=science,dc=nodomain?uid?base") {|ldap_src|
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        }
      end
    end

    def test_users_scope_one
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid?one") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      for user in USERS['user']
        open_ldap_src("ldap://localhost:#{PORT}/uid=#{user['uid']},ou=user,o=science,dc=nodomain?uid?one") {|ldap_src|
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        }
      end
    end

    def test_users_scope_sub
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid?sub") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      for user in USERS['user']
        open_ldap_src("ldap://localhost:#{PORT}/uid=#{user['uid']},ou=user,o=science,dc=nodomain?uid?sub") {|ldap_src|
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        }
      end
    end

    def test_users_scope_invalid_error
      assert_raise(RuntimeError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid?unknown") {|ldap_src|
          flunk
        }
      }
    end

    def test_users_filter_physics
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid??(memberOf=cn=physics,ou=group,o=science,dc=nodomain)") {|ldap_src|
        for user in USERS['user'].find_all{|user| user['group'] == 'physics' }
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
        for user in USERS['user'].find_all{|user| user['group'] != 'physics' }
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_filter_mathematics
      open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid??(memberOf=cn=mathmatics,ou=group,o=science,dc=nodomain)") {|ldap_src|
        for user in USERS['user'].find_all{|user| user['group'] == 'mathmatics' }
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
        for user in USERS['user'].find_all{|user| user['group'] != 'mathmatics' }
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_filter_invalid
      assert_raise(Net::LDAP::FilterSyntaxInvalidError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid??unknown") {|ldap_src|
          flunk
        }
      }
    end
  end

  class LDAPSourceTest < Test::Unit::TestCase
    include LDAPSourceTestMethod

    def test_wrong_search_bind
      auth = {
        method: :simple,
        username: 'no_dn',
        password: ''
      }
      assert_raise(RuntimeError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
          ldap_src.user? 'foo'    # to bind
          flunk
        }
      }

      auth = {
        method: :simple,
        username: 'cn=no_role,ou=support,o=science,dc=nodomain',
        password: 'open_sesame'
      }
      assert_raise(RuntimeError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
          ldap_src.user? 'foo'    # to bind
          flunk
        }
      }

      auth = {
        method: :simple,
        username: "cn=#{SEARCH['cn']},ou=support,o=science,dc=nodomain",
        password: 'invalid_pass'
      }
      assert_raise(RuntimeError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
          ldap_src.user? 'foo'    # to bind
          flunk
        }
      }
    end
  end

  class LDAPSourceSearchBindVerificationSkipTest < Test::Unit::TestCase
    include LDAPSourceTestMethod

    def setup
      super
      @search_bind_verification_skip = true
    end

    def test_wrong_search_bind_no_error
      auth = {
        method: :simple,
        username: 'no_dn',
        password: ''
      }
      #assert_raise(RuntimeError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
          ldap_src.user? 'foo'    # to bind
          #flunk
        }
      #}

      auth = {
        method: :simple,
        username: 'cn=no_role,ou=support,o=science,dc=nodomain',
        password: 'open_sesame'
      }
      #assert_raise(RuntimeError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
          ldap_src.user? 'foo'    # to bind
          #flunk
        }
      #}

      auth = {
        method: :simple,
        username: "cn=#{SEARCH['cn']},ou=support,o=science,dc=nodomain",
        password: 'invalid_pass'
      }
      #assert_raise(RuntimeError) {
        open_ldap_src("ldap://localhost:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
          ldap_src.user? 'foo'    # to bind
          #flunk
        }
      #}
    end
  end

  class LDAPSourceConfigTest < Test::Unit::TestCase
    def assert_decode_uri(expected_string, src_string)
      assert_equal(expected_string, RIMS::Password::LDAPSource.uri_decode(src_string))
    end
    private :assert_decode_uri

    def test_uri_decode
      assert_decode_uri('ou=user,o=science,dc=nodomain', 'ou=user,o=science,dc=nodomain')
      assert_decode_uri('(cn=Albert Einstein)', '(cn=Albert%20Einstein)')
      assert_decode_uri('(&(cn=Albert Einstein)(memberOf=cn=physics,ou=group,o=science,dc=nodomain))',
                        '(%26(cn=Albert%20Einstein)(memberOf=cn=physics%2cou=group%2co=science%2cdc=nodomain))')
      assert_decode_uri('+', '+')
    end
  end
end

# Local Variables:
# mode: Ruby
# indent-tabs-mode: nil
# End:
