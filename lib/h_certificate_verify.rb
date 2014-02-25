require './lib/h_type'

module Fuzzer
  module Handshake
    class CertificateVerify < Handshake::Type
      attr_reader :signed_struct

      def self.parse(data)
        CertificateVerify.new(data.force_encoding('ASCII-8BIT'))
      end

      public

      def initialize(signed_struct)
        super(15)
        @signed_struct = signed_struct
        @signed_struct = '' if signed_struct.nil?
        @signed_struct.force_encoding('ASCII-8BIT')
      end

      def to_wire
        @signed_struct
      end
    end
  end
end
