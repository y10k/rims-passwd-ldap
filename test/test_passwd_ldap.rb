# -*- coding: utf-8 -*-

require 'json'
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
    CONTAINER = YAML.load_file(File.join(File.dirname(__FILE__), '..', 'docker', 'container.yml'))
    HOST = (ENV.key? 'DOCKER_HOST') ? URI(ENV['DOCKER_HOST']).host : 'localhost'
    PORT = Integer(JSON.parse(`docker inspect #{CONTAINER['name']}`)[0]['NetworkSettings']['Ports']["#{CONTAINER['expose']}/tcp"][0]['HostPort'])
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
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid") {|ldap_src|
        assert_false(ldap_src.raw_password?)
      }
    end

    def test_users
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_wrong_password
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_false(ldap_src.compare_password(user['uid'], 'invalid_pass'), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_wrong_base_dn
      open_ldap_src("ldap://#{HOST}:#{PORT}/o=science,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      open_ldap_src("ldap://#{HOST}:#{PORT}/o=no_org,dc=nodomain?uid") {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_users_scope_base
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid?base") {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      for user in USERS['user']
        open_ldap_src("ldap://#{HOST}:#{PORT}/uid=#{user['uid']},ou=user,o=science,dc=nodomain?uid?base") {|ldap_src|
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        }
      end
    end

    def test_users_scope_one
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid?one") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      for user in USERS['user']
        open_ldap_src("ldap://#{HOST}:#{PORT}/uid=#{user['uid']},ou=user,o=science,dc=nodomain?uid?one") {|ldap_src|
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        }
      end
    end

    def test_users_scope_sub
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid?sub") {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }

      for user in USERS['user']
        open_ldap_src("ldap://#{HOST}:#{PORT}/uid=#{user['uid']},ou=user,o=science,dc=nodomain?uid?sub") {|ldap_src|
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        }
      end
    end

    def test_users_scope_invalid_error
      assert_raise(RuntimeError) {
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid?unknown") {|ldap_src|
          flunk
        }
      }
    end

    def test_users_filter_physics
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid??(memberOf=cn=physics,ou=group,o=science,dc=nodomain)") {|ldap_src|
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
      open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid??(memberOf=cn=mathmatics,ou=group,o=science,dc=nodomain)") {|ldap_src|
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
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid??unknown") {|ldap_src|
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
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
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
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
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
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
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
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
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
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
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
        open_ldap_src("ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid", search_bind_auth: auth) {|ldap_src|
          ldap_src.user? 'foo'    # to bind
          #flunk
        }
      #}
    end
  end

  class LDAPSourceConfigTest < Test::Unit::TestCase
    include LDAPExample

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

    def assert_parse_uri(expected_ldap_params, ldap_uri)
      assert_equal(expected_ldap_params, RIMS::Password::LDAPSource.parse_uri(ldap_uri))
    end
    private :assert_parse_uri

    def test_parse_uri
      assert_parse_uri({ host: 'localhost', port: 389 }, 'ldap:///')
      assert_parse_uri({ host: 'localhost', port: 636, encryption: true }, 'ldaps://')
      assert_parse_uri({ host: 'mydomain', port: 389 }, 'ldap://mydomain')
      assert_parse_uri({ host: 'mydomain', port: 38900 }, 'ldap://mydomain:38900')
      assert_parse_uri({ host: 'mydomain',
                         port: 389,
                         base_dn: 'ou=user,o=science,dc=nodomain'
                       }, 'ldap://mydomain/ou=user,o=science,dc=nodomain')
      assert_parse_uri({ host: 'mydomain',
                         port: 389,
                         base_dn: 'ou=user, o=science, dc=nodomain'
                       }, 'ldap://mydomain/ou=user,%20o=science,%20dc=nodomain')
      assert_parse_uri({ host: 'mydomain', port: 389, attribute: 'uid' }, 'ldap://mydomain/?uid')
      assert_parse_uri({ host: 'mydomain', port: 389, attribute: '?foo' }, 'ldap://mydomain/?%3ffoo')
      assert_parse_uri({ host: 'mydomain', port: 389, scope: 'base' }, 'ldap://mydomain/??base')
      assert_parse_uri({ host: 'mydomain', port: 389, scope: 'one' }, 'ldap://mydomain/??one')
      assert_parse_uri({ host: 'mydomain', port: 389, scope: 'sub' }, 'ldap://mydomain/??sub')
      assert_parse_uri({ host: 'mydomain', port: 389, filter: '(uid=einstein)' }, 'ldap://mydomain/???(uid=einstein)')
      assert_parse_uri({ host: 'mydomain', port: 389, filter: '(cn=Albert Einstein)' }, 'ldap://mydomain/???(cn=Albert%20Einstein)')
      assert_parse_uri({ host: 'mydomain',
                         port: 6360,
                         encryption: true,
                         base_dn: 'ou=user,o=science,dc=nodomain',
                         attribute: 'uid',
                         scope: 'base',
                         filter: '(uid=einstein)'
                       }, 'ldaps://mydomain:6360/ou=user,o=science,dc=nodomain?uid?base?(uid=einstein)')
    end

    def build_from_conf(config)
      ldap_src = RIMS::Password::LDAPSource.build_from_conf(config)

      logger = Logger.new(STDOUT)
      logger.level = ($DEBUG) ? Logger::DEBUG : Logger::FATAL
      ldap_src.logger = logger

      ldap_src.start
      begin
        yield(ldap_src)
      ensure
        ldap_src.stop
      end
    end
    private :build_from_conf

    def test_build_from_conf
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => false
      }
      build_from_conf(c) {|ldap_src|
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

    def test_build_from_conf_ldap_uri
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}/ou=user,o=science,dc=nodomain?uid?one?(memberOf=cn=physics,ou=group,o=science,dc=nodomain)",
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => false
      }
      build_from_conf(c) {|ldap_src|
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

    def test_build_from_conf_error_no_ldap_uri
      c = {
        #'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => false
      }
      assert_raise(RuntimeError) {
        build_from_conf(c) {|ldap_src|
          flunk
        }
      }
    end

    def test_build_from_conf_error_no_base_dn
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        #'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => false
      }
      assert_raise(RuntimeError) {
        build_from_conf(c) {|ldap_src|
          flunk
        }
      }
    end

    def test_build_from_conf_error_no_attribute
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        #'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => false
      }
      assert_raise(RuntimeError) {
        build_from_conf(c) {|ldap_src|
          flunk
        }
      }
    end

    def test_build_from_conf_scope_default
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        #'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => false
      }
      build_from_conf(c) {|ldap_src|
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

    def test_build_from_conf_no_filter
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        #'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => false
      }
      build_from_conf(c) {|ldap_src|
        for user in USERS['user']
          assert_true((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_true(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_build_from_conf_search_bind_verification_skip_default
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        #'search_bind_verification_skip' => false
      }
      build_from_conf(c) {|ldap_src|
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

    def test_build_from_conf_search_bind_verification_skip_enabled
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => {
          'method' => 'simple',
          'username' => SEARCH_USER,
          'password' => SEARCH_PASS
        },
        'search_bind_verification_skip' => true
      }
      build_from_conf(c) {|ldap_src|
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

    def test_build_from_conf_search_bind_auth_default_anonymous
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_verification_skip' => false
      }
      build_from_conf(c) {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end

    def test_build_from_conf_search_bind_auth_explicit_anonymous
      c = {
        'ldap_uri' => "ldap://#{HOST}:#{PORT}",
        'base_dn' => 'ou=user,o=science,dc=nodomain',
        'attribute' => 'uid',
        'scope' => 'one',
        'filter' => '(memberOf=cn=physics,ou=group,o=science,dc=nodomain)',
        'search_bind_auth' => { 'method' => 'anonymous' },
        'search_bind_verification_skip' => false
      }
      build_from_conf(c) {|ldap_src|
        for user in USERS['user']
          assert_false((ldap_src.user? user['uid']), "uid: #{user.inspect}")
          assert_nil(ldap_src.compare_password(user['uid'], user['userPassword']), "uid: #{user.inspect}")
        end
      }
    end
  end
end

# Local Variables:
# mode: Ruby
# indent-tabs-mode: nil
# End:
