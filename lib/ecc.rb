require 'openssl'

module CoDTLS
  # Class for multiplicaion on elliptic curve secp256r1 (prime256v1)
  class ECC
    # Does a scalar multiplication with a point on elliptic curve secp256r1.
    #
    # @param private_key [String] scalar for the multiplication (msb)
    # @param public_key [String] point for the multiplication (0x04, x, y)
    #
    # @return [String] the resulting point (0x04, x, y)
    def self.mult(private_key, public_key = nil)
      key = OpenSSL::BN.new(private_key, 2)

      group = OpenSSL::PKey::EC::Group.new('prime256v1')
      if public_key.nil?
        point = group.generator
      else
        bignum = OpenSSL::BN.new(public_key, 2)
        point = OpenSSL::PKey::EC::Point.new(group, bignum)
      end

      point.mul(key).to_bn.to_s(2)
    end
  end
end
