require './lib/h_type'

module Fuzzer
  module Handshake
    class Certificate < Handshake::Type
      attr_reader :certificate

      def self.parse(data)
        Certificate.new(data.force_encoding('ASCII-8BIT')[4..-1])
      end

      public

      def initialize(certificate = "\x00\x00\x5b\x30\x59\x30\x13\x06\x07\x2a\x86" \
        "\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42" \
        "\x00\x04\xd0\x55\xee\x14\x08\x4d\x6e\x06\x15\x59\x9d\xb5\x83\x91\x3e" \
        "\x4a\x3e\x45\x26\xa2\x70\x4d\x61\xf2\x7a\x4c\xcf\xba\x97\x58\xef\x9a" \
        "\xb4\x18\xb6\x4a\xfe\x80\x30\xda\x1d\xdc\xf4\xf4\x2e\x2f\x26\x31\xd0" \
        "\x43\xb1\xfb\x03\xe2\x2f\x4d\x17\xde\x43\xf9\xf9\xad\xee" \
        "\x70".force_encoding('ASCII-8BIT') )
        super(11)

        @certificate = certificate
        @certificate = '' if certificate.nil?
        @certificate.force_encoding('ASCII-8BIT')
      end

      def to_wire
        [@certificate.length].pack('N')[1..4] + @certificate
      end
    end
  end
end
