require 'socket'

require './lib/record'
require './lib/r_handshake'
require './lib/prf'

module Fuzzer
  module Engine
    $timeout = 0.2

    # Does the Handshake till the definied step. The following steps are available:
    #
    # Step | Keys   | send in do_steps           | return in tosend
    # ------------------------------------------------------------------------------------------
    #    0 | -      |                          - | ClientHello without Cookie
    #    1 | -      | ClientHello without Cookie | ClientHello with Cookie
    #    2 | avail. | ClientHello with Cookie    | ClientKeyExchange, ChangeCipherSpec, Finished
    #    3 | avail. | ClientKeyExchange          | ChangeCipherSpec, Finished
    #    4 | avail. | ChangeCipherSpec           | Finished
    #    5 | avail. | Finished                   | ApplicationData
    #    6 | avail. | ApplicationData            | CloseNotify
    #    7 | avail. | CloseNotify                | -
    #
    #                     Client           Server
    #                     ------           ------
    #       ClientHello  (seq=0) -------->
    #                            <-------- (seq=0)  HelloVerifyRequest
    #       ClientHello  (seq=1) -------->
    #      (mit cookie)
    #                            <-------- (seq=1)  ServerHello
    #                            <-------- (seq=2)  ServerKeyExchange
    #                            <-------- (seq=3)  ServerHelloDone
    # ClientKeyExchange  (seq=2) -------->
    #  ChangeCipherSpec          -------->
    #          Finished  (seq=3) -------->
    #                            <--------          ChangeCipherSpec
    #                            <-------- (seq=4)  Finished
    #  Application Data          <------->          Application Data
    #       CloseNotify          -------->
    #
    # @param socket [UDPSocket] a connected UDPSocket
    # @param step [Fixnum] from 0 .. 7
    #
    # @return [tosend, messages, [client_key, server_key, client_iv, server_iv]]
    #          tosend includes the next messages you need to send to continue.
    #          messages includes all send and received messages.
    #          if available the 3rd parameter contains an array of the keys.
    def self.do_steps(socket, step)
      fail StandardError, "Unkown Step: #{step}" if step > 7

      tosend = []
      messages = []

      tosend.push(Record::RecordHead.new(
        Record::HandshakeHead.new(
          # Fuzzer::Handshake::ClientHello.new(Time.now.to_i, 'ABCDEFGHIJKLMNOPQRSTUVWXYZAB'), 0), 0, 0).to_wire
          Handshake::ClientHello.new(1392817993, 'ABCDEFGHIJKLMNOPQRSTUVWXYZAB'), 0), 0, 0))
      return [tosend, messages, nil] if step == 0 || step < 0
      # ------------------

      # log message
      messages.push(tosend.shift)
      socket.send(messages.last.to_wire, 0)

      fail StandardError, 'Server didn\'t answer.' if select([socket], nil, nil, $timeout) == nil
      messages.push(Record::RecordHead.parse(socket.recvfrom(200)[0]))

      tosend.push(Record::RecordHead.new(
        Record::HandshakeHead.new(
          Handshake::ClientHello.new(1392817993, 'ABCDEFGHIJKLMNOPQRSTUVWXYZAB', messages.last.content.content.cookie), 0), 0, 1))
      return [tosend, messages, nil] if step == 1
      # ------------------

      # log message
      messages.push(tosend.shift)
      socket.send(messages.last.to_wire, 0)

      begin
        fail StandardError, 'Server didn\'t answer.' if select([socket], nil, nil, $timeout) == nil
        messages.push(Record::RecordHead.parse(socket.recvfrom(200)[0]))
      end until messages.last.content.content.class == Handshake::ServerHelloDone

      # messages.each do |n|
      #     if(n.content.content.class == Fuzzer::Handshake::CertificateRequest)
      #         tosend.push(Fuzzer::Record::Record.new(
      #             Fuzzer::Record::Handshake.new(
      #                 Fuzzer::Handshake::Certificate.new(), 1), 0, 2))
      #         tosend.push(message)
      #     end
      # end

      tosend.push(Record::RecordHead.new(
        Record::HandshakeHead.new(
          Handshake::ClientKeyExchange.new('Client_identity'), 1), 0, 2))

      # tosend.push(Fuzzer::Record::Record.new(
      #     Fuzzer::Record::Handshake.new(
      #         Fuzzer::Handshake::CertificateVerify.new('GRUSEL'), 3), 0, 4))
      # replies.push(message)

      tosend.push(Record::RecordHead.new(
        Record::ChangeCipherSpec.new(), 0, 3))

      data, keys = Engine.calc_finished(messages, tosend)

      tosend.push(Record::RecordHead.new(
        Record::HandshakeHead.new(
          Handshake::Finished.new(data), 2), 1, 0))
      return [tosend, messages, keys] if step == 2
      # ------------------

      # log message
      messages.push(tosend.shift)
      socket.send(messages.last.to_wire, 0)
      return [tosend, messages, keys] if step == 3
      # ------------------

      # log message
      messages.push(tosend.shift)
      socket.send(messages.last.to_wire, 0)
      return [tosend, messages, keys] if step == 4
      # ------------------

      # log message
      messages.push(tosend.shift)
      socket.send(messages.last.to_wire(keys[0], keys[2]), 0)
      fail StandardError, 'Server didn\'t answer.' if select([socket], nil, nil, $timeout) == nil
      messages.push(Record::RecordHead.parse(socket.recvfrom(200)[0]))
      fail StandardError, 'Server didn\'t answer.' if select([socket], nil, nil, $timeout) == nil
      messages.push(Record::RecordHead.parse(socket.recvfrom(200)[0], keys[1], keys[3]))

      # TODO check Server Finished

      tosend.push(Record::RecordHead.new(Record::AppData.new('Hello World :D'), 1, 1))

      return [tosend, messages, keys] if step == 5
      # ------------------

      messages.push(tosend.shift)
      socket.send(messages.last.to_wire(keys[0], keys[2]), 0)

      messages.push(Record::RecordHead.parse(socket.recvfrom(200)[0], keys[1], keys[3]))

      tosend.push(Record::RecordHead.new(Record::Alert.new(:fatal ,:close_notify), 1, 2))

      return [tosend, messages, keys] if step == 6
      # ------------------

      messages.push(tosend.shift)
      socket.send(messages.last.to_wire(keys[0], keys[2]), 0)

      messages.push(Record::RecordHead.parse(socket.recvfrom(200)[0], keys[1], keys[3]))

      return [tosend, messages, keys]

      # # p data.unpack('H*')[0]
      # newhandshakestring = ''.force_encoding('ASCII-8BIT')
      # replies.each do |n|
      #     if n.content.class == Fuzzer::Record::Handshake
      #         newhandshakestring += n.content.source
      #     end
      # end
      # newhandshakehash = (OpenSSL::Digest::Digest.new('sha256')<<newhandshakestring).digest()
      # # p OpenSSL::PRF.new(master_secret, 'server finished', newhandshakehash).get(12).unpack('H*')[0]

      # replies.push(Fuzzer::Record::Record.parse(socket.recvfrom(200)[0]))
      # temp = socket.recvfrom(200)[0]
      # replies.push(Fuzzer::Record::Record.parse(temp, key_s, iv_s))
      # [replies, [key_c, key_s, iv_c, iv_s], current_sequence_number_record]
    end

    def self.calc_finished(messages, tosend)
      pre_master_secret = ''.force_encoding('ASCII-8BIT')
      pre_master_secret += "\x00\x09"
      pre_master_secret += "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      pre_master_secret += "\x00\x09"
      pre_master_secret += 'secretPSK'
      c_rand = ''
      s_rand = ''
      messages.each do |n|
        if n.content.class == Record::HandshakeHead
          if n.content.content.class == Handshake::ClientHello
            c_rand = [n.content.content.time].pack('N')+n.content.content.random
          elsif n.content.content.class == Handshake::ServerHello
            s_rand = [n.content.content.time].pack('N')+n.content.content.random
          end
        end
      end
      fail StandardError, 'No Randomdata for master_secret' if c_rand == '' || s_rand == ''
      master_secret = OpenSSL::PRF.new(pre_master_secret, 'master secret', c_rand+s_rand).get(48)

      keyblock = OpenSSL::PRF.new(master_secret, 'key expansion', s_rand+c_rand).get(40)
      key_c = keyblock.slice!(0...16)
      key_s = keyblock.slice!(0...16)
      iv_c = keyblock.slice!(0...4)
      iv_s = keyblock.slice!(0...4)

      handshakestring = ''.force_encoding('ASCII-8BIT')
      messages[2..-1].each do |n|
        if n.content.class == Record::HandshakeHead
          handshakestring += n.content.source
        end
      end
      tosend.each do |n|
        if n.content.class == Record::HandshakeHead
          handshakestring += n.content.source
        end
      end
      handshakehash = (OpenSSL::Digest::Digest.new('sha256')<<handshakestring).digest()
      data = OpenSSL::PRF.new(master_secret, 'client finished', handshakehash).get(12)

      return [data, [key_c, key_s, iv_c, iv_s]]
    end
  end
end
