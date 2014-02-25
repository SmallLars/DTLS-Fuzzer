require './lib/h_type'

module Fuzzer
  module Handshake
    class ServerHello < Handshake::Type
      attr_reader :time, :random, :session

      def self.parse(data)
        data.force_encoding('ASCII-8BIT')
        data.slice!(0...2)
        t = data.slice!(0...4).unpack('N')[0]
        r = data.slice!(0...28)
        s = data.slice!(0...data.slice!(0).ord)
        ServerHello.new(t, r, s)
      end

      public

      def initialize(time, random, session)
        super(2)
        self.time = time
        self.random = random
        self.session = session
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
        if session.nil? || session.b.length.between?(1, 255)
          fail HandshakeError, 'Session length needs to be in 1 - 255'
        end
        @session = session
        @session.force_encoding('ASCII-8BIT')
      end

      def to_wire
        s = String.new("\xFE\xFD".force_encoding('ASCII-8BIT')) # Version 1.2
        s.concat([@time].pack('N'))
        s.concat(@random)
        s.concat([@session.length].pack('C'))
        s.concat(@session)
        s.concat("\xC0\xA8\x00".force_encoding('ASCII-8BIT'))
      end
    end
  end
end
