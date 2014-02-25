require './lib/h_type'

module Fuzzer
  module Handshake
    class ClientHello < Handshake::Type
      attr_reader :time, :random, :session, :cookie

      attr_accessor :session_length, :cookie_length

      public

      def initialize(time, random, value = nil, resume = false)
        super(1)
        self.time = time
        self.random = random
        if resume
          self.session = value
          self.cookie = nil
        else
          self.session = nil
          self.cookie = value
        end
      end

      def time=(time)
        fail HandshakeError, 'Invalid time value' if
          time.nil? || time > 0xFFFFFFFF
        @time = time
      end

      def random=(random)
        if random.nil? || random.b.length != 28
          fail HandshakeError, 'Random needs to have a length of 28 byte'
        else
          @random = random.force_encoding('ASCII-8BIT')
        end
      end

      def session=(session)
        @session = session
        unless @session.nil?
          @session.force_encoding('ASCII-8BIT')
          @session_length = session.length
          fail HandshakeError, 'Maximum session length is 255' if
            @session.length > 255
        end
      end

      def cookie=(cookie)
        @cookie = cookie
        unless @cookie.nil?
          @cookie.force_encoding('ASCII-8BIT')
          @cookie_length = cookie.length
          fail HandshakeError, 'Maximum cookie length is 255' if
            @cookie.length > 255
        end
      end

      def to_wire
        s = String.new("\xFE\xFD".force_encoding('ASCII-8BIT')) # Version 1.2
        s.concat([@time].pack('N'))
        s.concat(@random)
        if @session.nil?
          s.concat('00'.hex.chr)
        else
          s.concat([@session_length].pack('C'))
          s.concat(@session)
        end
        if @cookie.nil?
          s.concat('00'.hex.chr)
        else
          s.concat([@cookie_length].pack('C'))
          s.concat(@cookie)
        end
        s.concat('00'.hex.chr) # Ciphersuite Length
        s.concat('04'.hex.chr) # Ciphersuite Length
        s.concat('C0'.hex.chr) # Ciphersuite: TLS_PSK_WITH_AES_128_CCM_8
        s.concat('A8'.hex.chr) # Ciphersuite: TLS_PSK_WITH_AES_128_CCM_8
        s.concat('C0'.hex.chr) # Ciphersuite: TLS_PSK_ECDHE_WITH_AES_128_CCM_8
        s.concat('AC'.hex.chr) # Ciphersuite: TLS_PSK_ECDHE_WITH_AES_128_CCM_8
        s.concat('01'.hex.chr) # Compression Methods Length
        s.concat('00'.hex.chr) # No Compression
        s.concat('00'.hex.chr) # Extensions Length
        s.concat('1A'.hex.chr) # Extensions Length
        # ---
        s.concat('00'.hex.chr) # Client Certificate Type Extension
        s.concat('13'.hex.chr) # Client Certificate Type Extension
        s.concat('00'.hex.chr) # Client Certificate Type Extension Length
        s.concat('02'.hex.chr) # Client Certificate Type Extension Length
        s.concat('01'.hex.chr) # OpenPGP
        s.concat('02'.hex.chr) # Raw Public Key
        # ---
        s.concat('00'.hex.chr) # Server Certificate Type Extension
        s.concat('14'.hex.chr) # Server Certificate Type Extension
        s.concat('00'.hex.chr) # Server Certificate Type Extension Length
        s.concat('02'.hex.chr) # Server Certificate Type Extension Length
        s.concat('01'.hex.chr) # OpenPGP
        s.concat('02'.hex.chr) # Raw Public Key
        # ---
        s.concat('00'.hex.chr) # Supported Elliptic Curves Extension
        s.concat('0a'.hex.chr) # Supported Elliptic Curves Extension
        s.concat('00'.hex.chr) # Supported Elliptic Curves Extension Length
        s.concat('04'.hex.chr) # Supported Elliptic Curves Extension Length
        s.concat('00'.hex.chr) # Elliptic Curves Arrays Length
        s.concat('02'.hex.chr) # Elliptic Curves Arrays Length
        s.concat('00'.hex.chr) # Elliptic Curve TYP secp160r2
        s.concat('17'.hex.chr) # Elliptic Curve TYP secp160r2
        # ---
        s.concat('00'.hex.chr) # Supported Point Formats Extension
        s.concat('0B'.hex.chr) # Supported Point Formats Extension
        s.concat('00'.hex.chr) # Supported Point Formats Extension Length
        s.concat('02'.hex.chr) # Supported Point Formats Extension Length
        s.concat('01'.hex.chr) # Point Formats Arrays Length
        s.concat('00'.hex.chr) # Uncompressed Point
        s
      end
    end
  end
end
