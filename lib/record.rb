require './lib/r_alert'
require './lib/r_handshake'
require './lib/r_change_cipher_spec'
require './lib/r_application_data'
require './lib/ccm'

class Integer
  def itoh(bytecount)
    [self].pack('Q').reverse[(8-bytecount)..-1]
  end
end

class String
  def htoi
    ("\x00" * 8 + self)[-8..-1].reverse.unpack('Q')[0]
  end
end

module Fuzzer
  module Record
    class RecordHead
      attr_reader :content

      attr_accessor :content_type
      attr_accessor :protocol_version_major, :protocol_version_minor
      attr_accessor :epoch, :sequence_number
      attr_accessor :length

      def self.parse(data, key=nil, iv=nil)
        data.force_encoding('ASCII-8BIT')
        content_type = data.slice!(0...1).htoi
        protocol_version_major = data.slice!(0...1).htoi
        protocol_version_minor = data.slice!(0...1).htoi
        epoch = data.slice!(0...2).htoi
        sequence_number = data.slice!(0...6).htoi
        length = data.slice!(0...2).htoi
        if epoch > 0
            fail RecordError, 'Need Key and IV' if key.nil? || iv.nil?
            epoch = data.slice!(0...2).htoi
            sequence_number = data.slice!(0...6).htoi
            nonce = iv + epoch.itoh(2) + sequence_number.itoh(6)
            cleartext = data
            additional_data = epoch.itoh(2) + sequence_number.itoh(6)
            additional_data += content_type.chr
            additional_data += protocol_version_major.itoh(1)
            additional_data += protocol_version_minor.itoh(1)
            additional_data += (length-16).itoh(2)

            cipher = OpenSSL::CCM.new('AES', key, 8)
            data = cipher.decrypt(cleartext, nonce, additional_data)
            fail StandardError, 'Decrypt failed!' if data == ''
        end
        RecordHead.new(Type.parse(content_type, data), epoch, sequence_number)
      end

      public

      def initialize(content, epoch, sequence_number)
        @content_type = content.id
        @protocol_version_major = 254
        @protocol_version_minor = 253
        @epoch = epoch
        @sequence_number = sequence_number
        @length = content.to_wire.length
        @content = content
      end

      def to_wire(key = nil, iv = nil)
        s = ''
        s.force_encoding('ASCII-8BIT')
        s.concat(@content_type.itoh(1))
        s.concat(@protocol_version_major.itoh(1))
        s.concat(@protocol_version_minor.itoh(1))
        s.concat(@epoch.itoh(2))
        s.concat(@sequence_number.itoh(6))

        if @epoch > 0
          fail RecordError, 'Need Key and IV' if key.nil? || iv.nil?
          s.concat((@length + 8 + 8).itoh(2))
          s.concat(@epoch.itoh(2) + @sequence_number.itoh(6))
          nonce = iv + @epoch.itoh(2) + @sequence_number.itoh(6)
          cleartext = @content.to_wire
          additional_data = @epoch.itoh(2) + @sequence_number.itoh(6)
          additional_data += @content_type.chr
          additional_data += @protocol_version_major.itoh(1)
          additional_data += @protocol_version_minor.itoh(1)
          additional_data += @length.itoh(2);

          cipher = OpenSSL::CCM.new('AES', key, 8)
          cipherstring = cipher.encrypt(cleartext, nonce, additional_data)
          s.concat(cipherstring)
        else
          s.concat(@length.itoh(2))
          s.concat(@content.to_wire)
        end
        s
      end
    end
  end
end
