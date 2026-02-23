# frozen_string_literal: true

begin
  require 'io/wait' unless Puma::HAS_NATIVE_IO_WAIT
rescue LoadError
end

require 'open3'
require 'openssl'
require 'securerandom'

module Puma
  module MiniSSL
    OPENSSL_VERSION = OpenSSL::OPENSSL_VERSION
    OPENSSL_LIBRARY_VERSION = OpenSSL::OPENSSL_LIBRARY_VERSION

    # SSL3 is disabled in all OpenSSL versions that support Ruby 2.5+
    OPENSSL_NO_SSL3 = true
    OPENSSL_NO_TLS1 = false
    OPENSSL_NO_TLS1_1 = false

    # Remove any SSLError defined by C/Java extensions before redefining
    remove_const :SSLError if const_defined?(:SSLError, false)
    class SSLError < OpenSSL::SSL::SSLError; end

    # No-op, kept for backward compatibility
    def self.check; end

    # @version 5.0.0
    HAS_TLS1_3 = OpenSSL::SSL.const_defined?(:TLS1_3_VERSION)

    class Socket
      def initialize(ssl_socket, tcp_socket)
        @ssl_socket = ssl_socket
        @socket = tcp_socket
        @handshake_done = false
        @peercert = nil
        @failed_cert = nil
      end

      # @!attribute [r] to_io
      def to_io
        @socket
      end

      def closed?
        @socket.closed?
      end

      def readpartial(size)
        ensure_handshake
        @ssl_socket.readpartial(size)
      rescue OpenSSL::SSL::SSLError => e
        raise SSLError, e.message
      end

      def read_nonblock(size, *_)
        ensure_handshake
        @ssl_socket.read_nonblock(size)
      rescue IO::WaitReadable, IO::WaitWritable
        raise IO::EAGAINWaitReadable
      rescue OpenSSL::SSL::SSLError => e
        raise SSLError, e.message
      end

      def write(data)
        ensure_handshake
        @ssl_socket.write(data)
      rescue OpenSSL::SSL::SSLError => e
        raise SSLError, e.message
      end

      alias_method :syswrite, :write
      alias_method :<<, :write

      def write_nonblock(data, *_)
        write data
      end

      def flush
        @ssl_socket.flush
      end

      def close
        begin
          if @handshake_done
            @ssl_socket.flush rescue nil
            @ssl_socket.sysclose
          end
        rescue IOError, SystemCallError
          # nothing
        ensure
          @socket.close unless @socket.closed?
        end
      end

      # @!attribute [r] peeraddr
      def peeraddr
        @socket.peeraddr
      end

      # @return [OpenSSL::X509::Certificate, nil]
      # @!attribute [r] peercert
      def peercert
        return @peercert if @peercert
        @peercert = @ssl_socket.peer_cert || @failed_cert
      end

      private

      def ensure_handshake
        return if @handshake_done
        Thread.current[:puma_failed_cert] = nil
        begin
          @ssl_socket.accept
        rescue OpenSSL::SSL::SSLError => e
          raise SSLError, e.message
        ensure
          @handshake_done = true
          @failed_cert = Thread.current[:puma_failed_cert]
          Thread.current[:puma_failed_cert] = nil
        end
      end
    end

    class Context
      attr_accessor :verify_mode
      attr_reader :no_tlsv1, :no_tlsv1_1

      def initialize
        @no_tlsv1   = false
        @no_tlsv1_1 = false
        @key = nil
        @cert = nil
        @key_pem = nil
        @cert_pem = nil
        @reuse = nil
        @reuse_cache_size = nil
        @reuse_timeout = nil
      end

      def check_file(file, desc)
        raise ArgumentError, "#{desc} file '#{file}' does not exist" unless File.exist? file
        raise ArgumentError, "#{desc} file '#{file}' is not readable" unless File.readable? file
      end

      # PEM-based properties (all platforms)
      attr_reader :key
      attr_reader :key_password_command
      attr_reader :cert
      attr_reader :ca
      attr_reader :cert_pem
      attr_reader :key_pem
      attr_accessor :ssl_cipher_filter
      attr_accessor :ssl_ciphersuites
      attr_accessor :verification_flags

      attr_reader :reuse, :reuse_cache_size, :reuse_timeout

      def key=(key)
        check_file key, 'Key'
        @key = key
      end

      def key_password_command=(key_password_command)
        @key_password_command = key_password_command
      end

      def cert=(cert)
        check_file cert, 'Cert'
        @cert = cert
      end

      def ca=(ca)
        check_file ca, 'ca'
        @ca = ca
      end

      def cert_pem=(cert_pem)
        raise ArgumentError, "'cert_pem' is not a String" unless cert_pem.is_a? String
        @cert_pem = cert_pem
      end

      def key_pem=(key_pem)
        raise ArgumentError, "'key_pem' is not a String" unless key_pem.is_a? String
        @key_pem = key_pem
      end

      # Executes the command to return the password needed to decrypt the key.
      def key_password
        raise "Key password command not configured" if @key_password_command.nil?

        stdout_str, stderr_str, status = Open3.capture3(@key_password_command)

        return stdout_str.chomp if status.success?

        raise "Key password failed with code #{status.exitstatus}: #{stderr_str}"
      end

      # Controls session reuse.  Allowed values are as follows:
      # * 'off' - matches the behavior of Puma 5.6 and earlier.  This is included
      #   in case reuse 'on' is made the default in future Puma versions.
      # * 'dflt' - sets session reuse on, with OpenSSL default cache size of
      #   20k and default timeout of 300 seconds.
      # * 's,t' - where s and t are integer strings, for size and timeout.
      # * 's' - where s is an integer strings for size.
      # * ',t' - where t is an integer strings for timeout.
      #
      def reuse=(reuse_str)
        case reuse_str
        when 'off'
          @reuse = nil
        when 'dflt'
          @reuse = true
        when /\A\d+\z/
          @reuse = true
          @reuse_cache_size = reuse_str.to_i
        when /\A\d+,\d+\z/
          @reuse = true
          size, time = reuse_str.split ','
          @reuse_cache_size = size.to_i
          @reuse_timeout = time.to_i
        when /\A,\d+\z/
          @reuse = true
          @reuse_timeout = reuse_str.delete(',').to_i
        end
      end

      def check
        has_pem = @key || @key_pem || @cert || @cert_pem
        has_keystore = respond_to?(:keystore) && @keystore

        if has_keystore && !has_pem
          # JRuby keystore-only config
        elsif has_pem || !has_keystore
          raise "Key not configured" if @key.nil? && @key_pem.nil?
          raise "Cert not configured" if @cert.nil? && @cert_pem.nil?
        end
      end

      if IS_JRUBY
        # JRuby-specific: Java keystore/truststore properties (in addition to PEM above)
        attr_reader :keystore
        attr_reader :keystore_type
        attr_accessor :keystore_pass
        attr_reader :truststore
        attr_reader :truststore_type
        attr_accessor :truststore_pass
        attr_reader :cipher_suites
        attr_reader :protocols

        def keystore=(keystore)
          check_file keystore, 'Keystore'
          @keystore = keystore
        end

        def truststore=(truststore)
          unless truststore.eql?(:default)
            raise ArgumentError, "No such truststore file '#{truststore}'" unless File.exist?(truststore)
          end
          @truststore = truststore
        end

        def keystore_type=(type)
          raise ArgumentError, "Invalid keystore type: #{type.inspect}" unless ['pkcs12', 'jks', nil].include?(type)
          @keystore_type = type
        end

        def truststore_type=(type)
          raise ArgumentError, "Invalid truststore type: #{type.inspect}" unless ['pkcs12', 'jks', nil].include?(type)
          @truststore_type = type
        end

        def cipher_suites=(list)
          list = list.split(',').map(&:strip) if list.is_a?(String)
          @cipher_suites = list
        end

        alias_method :ssl_cipher_list, :cipher_suites
        alias_method :ssl_cipher_list=, :cipher_suites=

        def protocols=(list)
          list = list.split(',').map(&:strip) if list.is_a?(String)
          @protocols = list
        end
      end

      # disables TLSv1
      # @!attribute [w] no_tlsv1=
      def no_tlsv1=(tlsv1)
        raise ArgumentError, "Invalid value of no_tlsv1=" unless ['true', 'false', true, false].include?(tlsv1)
        @no_tlsv1 = tlsv1
      end

      # disables TLSv1 and TLSv1.1.  Overrides `#no_tlsv1=`
      # @!attribute [w] no_tlsv1_1=
      def no_tlsv1_1=(tlsv1_1)
        raise ArgumentError, "Invalid value of no_tlsv1_1=" unless ['true', 'false', true, false].include?(tlsv1_1)
        @no_tlsv1_1 = tlsv1_1
      end

    end

    VERIFY_NONE = 0
    VERIFY_PEER = 1
    VERIFY_FAIL_IF_NO_PEER_CERT = 2

    # https://github.com/openssl/openssl/blob/master/include/openssl/x509_vfy.h.in
    # /* Certificate verify flags */
    VERIFICATION_FLAGS = {
      "USE_CHECK_TIME"       => 0x2,
      "CRL_CHECK"            => 0x4,
      "CRL_CHECK_ALL"        => 0x8,
      "IGNORE_CRITICAL"      => 0x10,
      "X509_STRICT"          => 0x20,
      "ALLOW_PROXY_CERTS"    => 0x40,
      "POLICY_CHECK"         => 0x80,
      "EXPLICIT_POLICY"      => 0x100,
      "INHIBIT_ANY"          => 0x200,
      "INHIBIT_MAP"          => 0x400,
      "NOTIFY_POLICY"        => 0x800,
      "EXTENDED_CRL_SUPPORT" => 0x1000,
      "USE_DELTAS"           => 0x2000,
      "CHECK_SS_SIGNATURE"   => 0x4000,
      "TRUSTED_FIRST"        => 0x8000,
      "SUITEB_128_LOS_ONLY"  => 0x10000,
      "SUITEB_192_LOS"       => 0x20000,
      "SUITEB_128_LOS"       => 0x30000,
      "PARTIAL_CHAIN"        => 0x80000,
      "NO_ALT_CHAINS"        => 0x100000,
      "NO_CHECK_TIME"        => 0x200000
    }.freeze

    # Creates an OpenSSL::SSL::SSLContext from a Puma::MiniSSL::Context.
    # Handles both MRI-style (key/cert PEM files) and JRuby-style (Java keystore) configuration.
    def self.create_openssl_context(puma_ctx)
      ctx = OpenSSL::SSL::SSLContext.new

      cert = nil
      extra_chain_certs = []
      key = nil

      if puma_ctx.respond_to?(:keystore) && puma_ctx.keystore
        # JRuby keystore path: extract cert and key via Java APIs
        key, cert, extra_chain_certs = load_keystore(
          puma_ctx.keystore, puma_ctx.keystore_pass, puma_ctx.keystore_type
        )

        # Truststore for CA verification
        if puma_ctx.respond_to?(:truststore) && puma_ctx.truststore
          load_truststore(ctx, puma_ctx)
        end
      else
        # MRI path: PEM files or strings
        if puma_ctx.cert
          pem = File.read(puma_ctx.cert)
          certs = pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
          raise SSLError, "error in file '#{puma_ctx.cert}': no certificate found" if certs.empty?
          cert = OpenSSL::X509::Certificate.new(certs.first)
          extra_chain_certs = certs[1..].map { |c| OpenSSL::X509::Certificate.new(c) }
        elsif puma_ctx.cert_pem
          certs = puma_ctx.cert_pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
          raise SSLError, "error with parameter 'cert_pem': no certificate found" if certs.empty?
          cert = OpenSSL::X509::Certificate.new(certs.first)
          extra_chain_certs = certs[1..].map { |c| OpenSSL::X509::Certificate.new(c) }
        end

        password = puma_ctx.key_password_command ? puma_ctx.key_password : nil
        if puma_ctx.key
          key = OpenSSL::PKey.read(File.read(puma_ctx.key), password)
        elsif puma_ctx.key_pem
          key = OpenSSL::PKey.read(puma_ctx.key_pem, password)
        end

        # CA - set for verification and load eagerly to validate
        if puma_ctx.ca
          ctx.ca_file = puma_ctx.ca
          store = ctx.cert_store || OpenSSL::X509::Store.new
          store.add_file(puma_ctx.ca)
          ctx.cert_store = store

          # Also add CA certs to server's sent chain (matches original
          # SSL_CTX_load_verify_locations behavior with auto chain building)
          ca_pem = File.read(puma_ctx.ca)
          ca_certs = ca_pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
          ca_certs.each { |c| extra_chain_certs << OpenSSL::X509::Certificate.new(c) }
        end
      end

      # Set certificate, key, and chain on context
      if cert && key
        if ctx.respond_to?(:add_certificate)
          ctx.add_certificate(cert, key, extra_chain_certs)
        else
          # add_certificate is not available on JRuby's openssl.
          # extra_chain_cert= is also buggy on JRuby (breaks handshake),
          # so we only set cert and key here.
          ctx.cert = cert
          ctx.key = key
        end
      else
        ctx.cert = cert if cert
        ctx.key = key if key
      end

      # Verify mode with callback to capture failed certs
      if puma_ctx.verify_mode
        ctx.verify_mode = puma_ctx.verify_mode
        ctx.verify_callback = lambda do |preverify_ok, store_ctx|
          unless preverify_ok
            Thread.current[:puma_failed_cert] = store_ctx.current_cert
          end
          preverify_ok
        end
      end

      # Verification flags
      if puma_ctx.verification_flags
        ctx.cert_store ||= OpenSSL::X509::Store.new
        ctx.cert_store.flags = puma_ctx.verification_flags
      end

      # TLS version constraints
      ssl_options = OpenSSL::SSL::OP_CIPHER_SERVER_PREFERENCE | OpenSSL::SSL::OP_NO_COMPRESSION

      if ctx.respond_to?(:min_version=)
        if puma_ctx.no_tlsv1_1
          ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
        elsif puma_ctx.no_tlsv1
          ctx.min_version = OpenSSL::SSL::TLS1_1_VERSION
        end
      else
        ssl_options |= OpenSSL::SSL::OP_NO_SSLv2 | OpenSSL::SSL::OP_NO_SSLv3
        if puma_ctx.no_tlsv1
          ssl_options |= OpenSSL::SSL::OP_NO_TLSv1
        end
        if puma_ctx.no_tlsv1_1
          ssl_options |= OpenSSL::SSL::OP_NO_TLSv1 | OpenSSL::SSL::OP_NO_TLSv1_1
        end
      end

      ctx.options |= ssl_options

      # Ciphers
      cipher_filter = puma_ctx.ssl_cipher_filter
      cipher_filter ||= puma_ctx.cipher_suites if puma_ctx.respond_to?(:cipher_suites)

      if cipher_filter
        ctx.ciphers = cipher_filter
      else
        ctx.ciphers = "HIGH:!aNULL@STRENGTH"
      end

      if puma_ctx.ssl_ciphersuites && ctx.respond_to?(:ciphersuites=)
        ctx.ciphersuites = puma_ctx.ssl_ciphersuites
      end

      # JRuby protocol restrictions
      if puma_ctx.respond_to?(:protocols) && puma_ctx.respond_to?(:cipher_suites) && puma_ctx.protocols && ctx.respond_to?(:min_version=)
        versions = puma_ctx.protocols.map { |p| p.sub('TLSv', '').sub('.', '_') }
        # e.g. ['TLSv1.2'] -> set min and max to TLS 1.2
        min_v = versions.min
        max_v = versions.max
        version_map = { '1' => OpenSSL::SSL::TLS1_VERSION, '1_1' => OpenSSL::SSL::TLS1_1_VERSION,
                        '1_2' => OpenSSL::SSL::TLS1_2_VERSION }
        version_map['1_3'] = OpenSSL::SSL::TLS1_3_VERSION if HAS_TLS1_3
        ctx.min_version = version_map[min_v] if version_map[min_v]
        ctx.max_version = version_map[max_v] if version_map[max_v]
      end

      # Session reuse
      if puma_ctx.reuse
        ctx.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_SERVER
        ctx.session_cache_size = puma_ctx.reuse_cache_size if puma_ctx.reuse_cache_size
        ctx.timeout = puma_ctx.reuse_timeout if puma_ctx.reuse_timeout
      else
        ctx.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_OFF
      end

      # Session ID context
      ctx.session_id_context = SecureRandom.bytes(32)

      ctx
    rescue OpenSSL::OpenSSLError => e
      raise SSLError, e.message unless e.is_a?(SSLError)
      raise
    end

    if IS_JRUBY
      # Loads a Java KeyStore and returns [key, cert, extra_chain_certs]
      def self.load_keystore(path, password, type = nil)
        type ||= 'jks'
        ks = java.security.KeyStore.getInstance(type)
        password_chars = password&.to_java&.toCharArray

        fis = java.io.FileInputStream.new(path)
        begin
          ks.load(fis, password_chars)
        ensure
          fis.close
        end

        ks.aliases.each do |ali|
          next unless ks.isKeyEntry(ali)

          java_key = ks.getKey(ali, password_chars)
          java_chain = ks.getCertificateChain(ali)

          # Convert PKCS#8 DER to PEM for OpenSSL::PKey.read
          b64 = java.util.Base64.getEncoder.encodeToString(java_key.getEncoded)
          pem_key = "-----BEGIN PRIVATE KEY-----\n#{b64.scan(/.{1,64}/).join("\n")}\n-----END PRIVATE KEY-----\n"
          key = OpenSSL::PKey.read(pem_key)

          certs = java_chain.map { |c| OpenSSL::X509::Certificate.new(String.from_java_bytes(c.getEncoded)) }

          return [key, certs.first, certs[1..] || []]
        end

        raise SSLError, "No private key entry found in keystore '#{path}'"
      end

      # Loads a Java TrustStore into the SSLContext's cert_store
      def self.load_truststore(ctx, puma_ctx)
        return if puma_ctx.truststore.eql?(:default)

        type = puma_ctx.truststore_type || 'jks'
        ts = java.security.KeyStore.getInstance(type)
        password_chars = puma_ctx.truststore_pass&.to_java&.toCharArray

        fis = java.io.FileInputStream.new(puma_ctx.truststore)
        begin
          ts.load(fis, password_chars)
        ensure
          fis.close
        end

        store = ctx.cert_store || OpenSSL::X509::Store.new
        ts.aliases.each do |ali|
          next unless ts.isCertificateEntry(ali)
          java_cert = ts.getCertificate(ali)
          store.add_cert(OpenSSL::X509::Certificate.new(String.from_java_bytes(java_cert.getEncoded)))
        end
        ctx.cert_store = store
      end
    end

    class Server
      def initialize(socket, ctx)
        @socket = socket
        @ctx = ctx
        @openssl_ctx = MiniSSL.create_openssl_context(ctx)
      end

      def accept
        @ctx.check
        io = @socket.accept
        ssl_socket = OpenSSL::SSL::SSLSocket.new(io, @openssl_ctx)
        Socket.new ssl_socket, io
      end

      def accept_nonblock
        @ctx.check
        io = @socket.accept_nonblock
        ssl_socket = OpenSSL::SSL::SSLSocket.new(io, @openssl_ctx)
        Socket.new ssl_socket, io
      end

      # @!attribute [r] to_io
      def to_io
        @socket
      end

      # @!attribute [r] addr
      # @version 5.0.0
      def addr
        @socket.addr
      end

      def close
        @socket.close unless @socket.closed?       # closed? call is for Windows
      end

      def closed?
        @socket.closed?
      end
    end
  end
end
