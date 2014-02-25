require './lib/r_type'
require './lib/h_client_hello'
require './lib/h_hello_verify_request'
require './lib/h_server_hello'
require './lib/h_certificate'
require './lib/h_key_exchange'
require './lib/h_certificate_request'
require './lib/h_server_hello_done'
require './lib/h_certificate_verify'
require './lib/h_finished'

module Fuzzer
  module Record
    class HandshakeHead < Record::Type
      attr :source

      attr_reader :content

      attr_accessor :content_type, :seq, :length

      def self.parse(data)
        source = data.dup
        type = data[0].ord
        seq = data[4..5].unpack('n')[0]
        HandshakeHead.new(Handshake::Type.parse(type, data[12..-1]), seq, source)
      end

      def initialize(content, seq, source = '')
        super(22)
        @source = source
        @content = content
        @content_type = content.id
        @seq = seq
        @length = content.to_wire.length
      end

      def source
        if @source == ''
          to_wire
        else
          @source
        end
      end

      def to_wire
        hmsg = @content.id.chr
        hmsg += [@length].pack('N')[1..3]
        hmsg += [@seq].pack('n')          # message_seq
        hmsg += "\x00\x00\x00"            # fragment_offset
        hmsg += [@length].pack('N')[1..3] # fragment_length
        hmsg += @content.to_wire
      end
    end
  end
end
