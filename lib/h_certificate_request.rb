require './lib/h_type'

module Fuzzer
  module Handshake
    class CertificateRequest < Handshake::Type
      attr_reader :certificate_request

      def self.parse(data)
        CertificateRequest.new(data.force_encoding('ASCII-8BIT'))
      end

      public

      def initialize(certificate_request)
        super(13)
        @certificate_request = certificate_request
        @certificate_request = '' if certificate_request.nil?
        @certificate_request.force_encoding('ASCII-8BIT')
      end

      def to_wire
        "\x01\x40\x00\x02\x04\x03\x00\x00"
      end
    end
  end
end
