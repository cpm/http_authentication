module HttpAuthentication
  module Digest
    extend self

    module ControllerMethods
      def authenticate_or_request_with_http_digest(realm = "Application", &password_procedure)
        authenticate_with_http_digest(realm, &password_procedure) || request_http_digest_authentication(realm)
      end

      # Authenticate with HTTP Digest, returns true or false
      def authenticate_with_http_digest(realm = "Application", &password_procedure)
        HttpAuthentication::Digest.authenticate(self, realm, &password_procedure)
      end

      # Render output including the HTTP Digest authentication header
      def request_http_digest_authentication(realm = "Application", message = nil)
        HttpAuthentication::Digest.authentication_request(self, realm, message)
      end
    end

    # Returns false on a valid response, true otherwise
    def authenticate(controller, realm, &password_procedure)
      authorization(controller.request) && validate_digest_response(controller.request, realm, &password_procedure)
    end

    def authorization(request)
      request.env['HTTP_AUTHORIZATION']   ||
      request.env['X-HTTP_AUTHORIZATION'] ||
      request.env['X_HTTP_AUTHORIZATION'] ||
      request.env['REDIRECT_X_HTTP_AUTHORIZATION']
    end

    # Raises error unless the request credentials response value matches the expected value.
    # First try the password as a ha1 digest password. If this fails, then try it as a plain
    # text password.
    def validate_digest_response(request, realm, &password_procedure)
      credentials = decode_credentials_header(request)
      valid_nonce = validate_nonce(request, credentials[:nonce])

      if valid_nonce && realm == credentials[:realm] && opaque == credentials[:opaque]
        password = password_procedure.call(credentials[:username])
        method = request.env['rack.methodoverride.original_method'] || request.env['REQUEST_METHOD']

       [true, false].any? do |password_is_ha1|
         expected = expected_response(method, request.env['REQUEST_URI'], credentials, password, password_is_ha1)
         expected == credentials[:response]
       end
      end
    end

    # Returns the expected response for a request of +http_method+ to +uri+ with the decoded +credentials+ and the expected +password+
    # Optional parameter +password_is_ha1+ is set to +true+ by default, since best practice is to store ha1 digest instead
    # of a plain-text password.
    def expected_response(http_method, uri, credentials, password, password_is_ha1=true)
      ha1 = password_is_ha1 ? password : ha1(credentials, password)
      ha2 = ::Digest::MD5.hexdigest([http_method.to_s.upcase, uri].join(':'))
      ::Digest::MD5.hexdigest([ha1, credentials[:nonce], credentials[:nc], credentials[:cnonce], credentials[:qop], ha2].join(':'))
    end

    def ha1(credentials, password)
      ::Digest::MD5.hexdigest([credentials[:username], credentials[:realm], password].join(':'))
    end

    def encode_credentials(http_method, credentials, password, password_is_ha1)
      credentials[:response] = expected_response(http_method, credentials[:uri], credentials, password, password_is_ha1)
      "Digest " + credentials.sort_by {|x| x[0].to_s }.inject([]) {|a, v| a << "#{v[0]}='#{v[1]}'" }.join(', ')
    end

    def decode_credentials_header(request)
      decode_credentials(authorization(request))
    end

    def decode_credentials(header)
      header.to_s.gsub(/^Digest\s+/,'').split(',').inject({}) do |hash, pair|
        key, value = pair.split('=', 2)
        hash[key.strip.to_sym] = value.to_s.gsub(/^"|"$/,'').gsub(/'/, '')
        hash
      end
    end

    def authentication_header(controller, realm)
      controller.headers["WWW-Authenticate"] = %(Digest realm="#{realm}", qop="auth", algorithm=MD5, nonce="#{nonce}", opaque="#{opaque}")
    end

    def authentication_request(controller, realm, message = nil)
      message ||= "HTTP Digest: Access denied.\n"
      authentication_header(controller, realm)
      controller.__send__ :render, :text => message, :status => :unauthorized
    end

    # Uses an MD5 digest based on time to generate a value to be used only once.
    #
    # A server-specified data string which should be uniquely generated each time a 401 response is made.
    # It is recommended that this string be base64 or hexadecimal data.
    # Specifically, since the string is passed in the header lines as a quoted string, the double-quote character is not allowed.
    #
    # The contents of the nonce are implementation dependent.
    # The quality of the implementation depends on a good choice.
    # A nonce might, for example, be constructed as the base 64 encoding of
    #
    # => time-stamp H(time-stamp ":" ETag ":" private-key)
    #
    # where time-stamp is a server-generated time or other non-repeating value,
    # ETag is the value of the HTTP ETag header associated with the requested entity,
    # and private-key is data known only to the server.
    # With a nonce of this form a server would recalculate the hash portion after receiving the client authentication header and
    # reject the request if it did not match the nonce from that header or
    # if the time-stamp value is not recent enough. In this way the server can limit the time of the nonce's validity.
    # The inclusion of the ETag prevents a replay request for an updated version of the resource.
    # (Note: including the IP address of the client in the nonce would appear to offer the server the ability
    # to limit the reuse of the nonce to the same client that originally got it.
    # However, that would break proxy farms, where requests from a single user often go through different proxies in the farm.
    # Also, IP address spoofing is not that hard.)
    #
    # An implementation might choose not to accept a previously used nonce or a previously used digest, in order to
    # protect against a replay attack. Or, an implementation might choose to use one-time nonces or digests for
    # POST or PUT requests and a time-stamp for GET requests. For more details on the issues involved see Section 4
    # of this document.
    #
    # The nonce is opaque to the client. Composed of Time, and hash of Time with secret
    # key from the Rails session secret generated upon creation of project. Ensures
    # the time cannot be modifed by client.
    def nonce(time = Time.now)
      t = time.to_i
      hashed = [t, secret_key]
      digest = ::Digest::MD5.hexdigest(hashed.join(":"))
      ActiveSupport::Base64.encode64("#{t}:#{digest}").gsub("\n", '')
    end

    # Might want a shorter timeout depending on whether the request
    # is a PUT or POST, and if client is browser or web service.
    # Can be much shorter if the Stale directive is implemented. This would
    # allow a user to use new nonce without prompting user again for their
    # username and password.
    def validate_nonce(request, value, seconds_to_timeout=5*60)
      t = ActiveSupport::Base64.decode64(value).split(":").first.to_i
      nonce(t) == value && (t - Time.now.to_i).abs <= seconds_to_timeout
    end

    # Opaque based on random generation - but changing each request?
    def opaque()
      ::Digest::MD5.hexdigest(secret_key)
    end

    # Set in /initializers/session_store.rb, and loaded even if sessions are not in use.
    def secret_key
      ActionController::Base.session_options[:secret]
    end
  end
end

end
