# -*- coding: utf-8 -*-

require 'net/ldap'
require 'rims'
require 'rims/passwd/ldap/version'
require 'uri'

# to enable LDAP pass-source plug-in, add the entry of
# <tt>rims/passwd/ldap</tt> to <tt>load_libraries</tt> list.
#
#  ex.
#     load_libraries:
#       - rims/passwd/ldap
#
class RIMS::Password::LDAPSource < RIMS::Password::Source
  def initialize(host, port, base_dn, attr, scope: 'sub', filter: nil,
                 search_bind_auth: { :method => :anonymous },
                 search_bind_verification_skip: false,
                 encryption: false)
    @host = host
    @port = port
    @base_dn = base_dn
    @attr = attr
    @scope_src = scope
    @filter_src = filter
    @search_bind_auth = search_bind_auth
    @search_bind_verification_skip = search_bind_verification_skip
    @encryption = encryption
  end

  def start
    scheme = @encryption ? 'ldaps' : 'ldap'
    @logger.info("LDAP pass-source: #{scheme}://#{@host}:#{@port}/#{@base_dn}?#{@attr}?#{@scope_src}?#{@filter_src}")

    case (@scope_src)
    when 'base'
      @scope = Net::LDAP::SearchScope_BaseObject
    when 'one'
      @scope = Net::LDAP::SearchScope_SingleLevel
    when 'sub'
      @scope = Net::LDAP::SearchScope_WholeSubtree
    else
      raise "unknown ldap search scope: #{@scope_src}"
    end

    if (@filter_src) then
      filter = Net::LDAP::Filter.construct(@filter_src)
      @filter_factory = proc{|username|
        Net::LDAP::Filter.eq(@attr, username) & filter
      }
    else
      @filter_factory = proc{|username|
        Net::LDAP::Filter.eq(@attr, username)
      }
    end
  end

  def raw_password?
    false
  end

  def ldap_open
    options = { host: @host, port: @port }
    if (@search_bind_verification_skip) then
      options[:auth] = @search_bind_auth
    end
    if (@encryption) then
      options[:encryption] = :simple_tls
    end

    Net::LDAP.open(options) {|ldap|
      unless (@search_bind_verification_skip) then
        # implicit bind of Net::LDAP.open has no error handling.
        # explicit 2nd bind is required to check bind error.
        if (@logger.debug?) then
          auth = @search_bind_auth.dup
          auth.delete(:password)
          @logger.debug("LDAP bind: #{auth.inspect}")
        end
        ldap.bind(@search_bind_auth) or raise "failed to bind to search: #{ldap.get_operation_result}"
        @logger.debug("LDAP bind OK")
      end

      yield(ldap)
    }
  end
  private :ldap_open

  def search(ldap, username)
    user_filter = @filter_factory.call(username)
    @logger.debug("LDAP search #{@base_dn} #{@attr} #{@scope} #{user_filter}") if @logger.debug?
    if (users = ldap.search(base: @base_dn, attributes: [ @attr ], scope: @scope, filter: user_filter)) then
      unless (users.empty?) then
        user_dn = users.first.dn
        @logger.info("found a LDAP user: #{user_dn}")
        return user_dn
      else
        @logger.debug("LDAP search result: not found") if @logger.debug?
      end
    else
      @logger.debug("LDAP search result: no entries") if @logger.debug?
    end

    nil
  end
  private :search

  def user?(username)
    ldap_open{|ldap|
      if (search(ldap, username)) then
        true
      else
        false
      end
    }
  end

  def compare_password(username, password)
    ldap_open{|ldap|
      if (user_dn = search(ldap, username)) then
        if (ldap.bind(method: :simple, username: user_dn, password: password)) then
          true
        else
          false
        end
      end
    }
  end

  class << self
    def uri_decode(string)
      string.gsub(/%(\h)(\h)/) { [$&[1, 2].hex].pack('C') }.force_encoding(string.encoding)
    end

    def parse_uri(uri_string)
      ldap_params = {}

      ldap_uri = URI.parse(uri_string)
      case (ldap_uri)
      when URI::LDAPS
        ldap_params[:encryption] = true
      when URI::LDAP
        # OK
      else
        raise "not a LDAP URI: #{uri_string}"
      end

      ldap_params[:host] = ldap_uri.host || 'localhost'
      ldap_params[:port] = ldap_uri.port or raise "required LDAP port: #{uri_string}"
      ldap_params[:base_dn] = uri_decode(ldap_uri.dn) if (ldap_uri.dn && ! ldap_uri.dn.empty?)
      ldap_params[:attribute] = uri_decode(ldap_uri.attributes) if ldap_uri.attributes
      ldap_params[:scope] = uri_decode(ldap_uri.scope) if ldap_uri.scope
      ldap_params[:filter] = uri_decode(ldap_uri.filter) if ldap_uri.filter

      ldap_params
    end

    # configuration entries:
    # * <tt>"ldap_uri"</tt>
    # * <tt>"base_dn"</tt>
    # * <tt>"attribute"</tt>
    # * <tt>"scope"</tt>
    # * <tt>"filter"</tt>
    # * <tt>"search_bind_auth"</tt>
    #     * <tt>"method"</tt>
    #     * <tt>"username"</tt>
    #     * <tt>"password"</tt>
    # * <tt>"search_bind_verification_skip"</tt>
    #
    def build_from_conf(config)
      unless (config.key? 'ldap_uri') then
        raise 'required ldap_uri parameter at LDAP pass-source configuration.'
      end
      ldap_params = parse_uri(config['ldap_uri'])
      ldap_args = []

      for name in [ :host, :port ]
        value = ldap_params.delete(name) or raise "internal error: #{name}"
        ldap_args << value
      end

      for name in [ :base_dn, :attribute ]
        value = ldap_params.delete(name)
        if (config.key? name.to_s) then
          value = config[name.to_s]
        end
        unless (value) then
          raise "required #{name} parameter at LDAP pass-source configuration."
        end
        ldap_args << value
      end

      for name in [ :scope, :filter, :search_bind_verification_skip ]
        if (config.key? name.to_s) then
          ldap_params[name] = config[name.to_s]
        end
      end

      if (config.key? 'search_bind_auth') then
        case (config['search_bind_auth']['method'])
        when 'anonymous'
          auth = { method: :anonymous }
        when 'simple'
          auth = { method: :simple }
          auth[:username] = config['search_bind_auth']['username'] or raise 'required serach bind username at LDAP pass-source configuration.'
          auth[:password] = config['search_bind_auth']['password'] or raise 'required search bind password at LDAP pass-source configuration.'
        else
          raise "unknown or unsupported bind method type: #{config['search_bind_auth'].inspect}"
        end
        ldap_params[:search_bind_auth] = auth
      end

      self.new(*ldap_args, **ldap_params)
    end
  end

  RIMS::Authentication.add_plug_in('ldap', self)
end

# Local Variables:
# mode: Ruby
# indent-tabs-mode: nil
# End:
