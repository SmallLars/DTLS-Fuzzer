require 'openssl'

module OpenSSL
  class PRFError < StandardError
  end

  # PRF(secret, label, seed) = P_<hash>(secret, label + seed)
  #
  # P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
  #                        HMAC_hash(secret, A(2) + seed) +
  #                        HMAC_hash(secret, A(3) + seed) + ...
  #
  # A() is defined as:
  #       A(0) = seed
  #       A(i) = HMAC_hash(secret, A(i-1))
  class PRF
    def initialize(secret, label, seed)
      @secret = secret.force_encoding('ASCII-8BIT')
      @seed = label.force_encoding('ASCII-8BIT')
      @seed += seed.force_encoding('ASCII-8BIT')
      @digest = OpenSSL::Digest.new('sha256')
      @buffer = ''.force_encoding('ASCII-8BIT')
      @a_x = @seed.dup
    end

    def get(bytes)
      output = ''.force_encoding('ASCII-8BIT')
      while output.length < bytes do
        output += @buffer.slice!(0...(bytes - output.length))
        fillBuffer if @buffer.length == 0
      end
      output
    end

    def fillBuffer
      @a_x = OpenSSL::HMAC.digest(@digest, @secret, @a_x)
      @buffer = OpenSSL::HMAC.digest(@digest, @secret, @a_x + @seed)
      @buffer.force_encoding('ASCII-8BIT')
    end
  end
end
