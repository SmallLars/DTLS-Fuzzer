require './lib/r_type'

module Fuzzer
  module Record
    class AppData < Record::Type
      attr_reader :value

      def self.parse(data)
        data.force_encoding('ASCII-8BIT')
        AppData.new(data)
      end

      public

      def initialize(data)
        super(23)
        data = '' if data.nil?
        @value = data
      end

      def to_wire
        @value
      end
    end
  end
end
