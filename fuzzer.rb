require 'socket'

require './lib/engine'

$SERVER_IP = '127.0.0.1'
$DTLS_PORT = 20220

module Fuzzer
  class Fuzzer
    def self.simple_connect
      socket = UDPSocket.new
      socket.connect($SERVER_IP, $DTLS_PORT)
      Engine.do_steps(socket, 7)
      puts 'Test: simple_connect passed'
      socket.close
    end

    def self.replay_attack_test
      # initialization
      socket = UDPSocket.new
      socket.connect($SERVER_IP, $DTLS_PORT)
      tosend, messages, keys = Engine.do_steps(socket, 6)
      # send old msg again
      socket.send(messages[2].to_wire, 0)
      # check for correct behavior
      if select([socket], nil, nil, $timeout) == nil
        puts 'Test: replay_attack_test passed. got no answer'
        socket.close
        return
      end
      response = Record::RecordHead.parse(socket.recvfrom(200)[0], keys[1], keys[3])
      puts "WARNING: Replay Attack successfull. answer: #{response.inspect}"
      socket.close
    end

    def self.finished_wrong_seq
      # initialization
      socket = UDPSocket.new
      socket.connect($SERVER_IP, $DTLS_PORT)
      tosend, messages, keys = Engine.do_steps(socket, 4)
      # changing values
      tosend[0].epoch = 1
      tosend[0].sequence_number = 1 + Random.rand((2**48)-1) # <--- should be 0
      # continue handshake
      socket.send(tosend[0].to_wire(keys[0], keys[2]), 0)
      # check for correct behavior
      if select([socket], nil, nil, $timeout) == nil
        puts 'Test: unencrypted_finished_wrong_seq passed. got no answer'
        socket.close
        return
      end
      response = Record::RecordHead.parse(socket.recvfrom(200)[0])
      if response.content.class == Record::Alert
        puts "Test: unencrypted_finished_wrong_seq passed. got alert: #{response.inspect}"
        socket.close
        return
      end
      puts "WARNING: encrypted Finished paket with wrong sequence number " \
            "(#{tosend[0].sequence_number}) accepted. answer: #{response.inspect}"
      socket.close
    end

    def self.unencrypted_finished
      # initialization
      socket = UDPSocket.new
      socket.connect($SERVER_IP, $DTLS_PORT)
      tosend, messages, keys = Engine.do_steps(socket, 4)
      # changing values
      tosend[0].epoch = 0
      tosend[0].sequence_number = 4
      # continue handshake
      socket.send(tosend[0].to_wire, 0)
      # check for correct behavior
      if select([socket], nil, nil, $timeout) == nil
        puts 'Test: unencrypted_finished passed. got no answer'
        socket.close
        return
      end
      response = Record::RecordHead.parse(socket.recvfrom(200)[0])
      if response.content.class != Record::ChangeCipherSpec
        puts "Test: unencrypted_finished passed. answer: #{response.inspect}"
        socket.close
        return
      end
      puts "WARNING: unencrypted Finished paket accepted. answer: #{response.inspect}"
      socket.close
    end

    def self.wrong_seq
      # initialization
      socket = UDPSocket.new
      socket.connect($SERVER_IP, $DTLS_PORT)
      tosend, messages, keys = Engine.do_steps(socket, 5)
      # changing values
      tosend[0].sequence_number = 2 + Random.rand((2**48)-2) # <--- should be 2
      # continue handshake
      socket.send(tosend[0].to_wire(keys[0], keys[2]), 0)
      # check for correct behavior
      if select([socket], nil, nil, $timeout) == nil
        puts 'Test: unencrypted_finished passed'
        socket.close
        return
      end
      response = Record::RecordHead.parse(socket.recvfrom(200)[0], keys[1], keys[3])
      puts "WARNING: encrypted ApplicationData packet with wrong sequence number " \
           "(#{tosend[0].sequence_number}) accepted. answer: #{response.inspect}"
      socket.close
    end

    def self.wrong_finished
      # initialization
      socket = UDPSocket.new
      socket.connect($SERVER_IP, $DTLS_PORT)
      tosend, messages, keys = Engine.do_steps(socket, 4)
      # changing values
      tosend[0].content.content.value = 'New_value123'
      # continue handshake
      socket.send(tosend[0].to_wire(keys[0], keys[2]), 0)
      # check for correct behavior
      if select([socket], nil, nil, $timeout) == nil
        puts 'Test: wrong_finished passed. got no answer'
        socket.close
        return
      end
      response = Record::RecordHead.parse(socket.recvfrom(200)[0])
      if response.content.class == Record::Alert
        puts "Test: wrong_finished passed. got alert: #{response.inspect}"
        socket.close
        return
      end
      puts "WARNING: finished packet with wrong finished value accepted. answer: #{response.inspect}"
      socket.close
    end

    # WORK IN PROGRESS FOR FOLLOWING TESTS

    def self.cookie_test
      200.times do |n|
        socket = UDPSocket.new
        socket.connect($SERVER_IP, $DTLS_PORT)
        tosend, messages, keys = Engine.do_steps(socket, 0)
        tosend[0].content.content.cookie = ''
        temp = ''
        Random.rand(64).times do |n|
          temp += Random.rand(256).chr
        end
        tosend[0].content.content.cookie = temp
        tosend[0].content.content.cookie_length += (1 - Random.rand(2))
        socket.send(tosend[0].to_wire, 0)
        value = select([socket], nil, nil, $timeout)
        unless value.nil?
          response = Record::RecordHead.parse(socket.recvfrom(200)[0])
          puts "WARNING: Cookie Attack successfull. answer: #{response.inspect}" if
            response.content.content.class != Handshake::HelloVerifyRequest
        end
        socket.close
      end
      return true
    end

    def self.after_cookie_test # TODO: NOT WORKING
      200.times do |n|
        socket = UDPSocket.new
        socket.connect($SERVER_IP, $DTLS_PORT)
        tosend, messages, keys = Engine.do_steps(socket, 2)
        tosend[0].content.content.psk_hint_length += (1 - Random.rand(2))
        socket.send(tosend[0].to_wire, 0)
        value = select([socket], nil, nil, $timeout)
        errormessage = 'PSK Hint Length Attack'
        fail StandardError, errormessage if value.nil?
        response = Record::RecordHead.parse(socket.recvfrom(200)[0])
        fail StandardError, errormessage if response.content.class != Record::Alert
        socket.close
      end
    end

    def self.server_explode_test # Warning: port collision very possible
      200.times do |n|
        socket = UDPSocket.new
        socket.connect($SERVER_IP, $DTLS_PORT)
        Engine.do_steps(socket, 2)
        socket.close
      end
    end
  end
end

puts ''
Fuzzer::Fuzzer.simple_connect
puts ''
Fuzzer::Fuzzer.replay_attack_test
puts ''
Fuzzer::Fuzzer.unencrypted_finished
puts ''
Fuzzer::Fuzzer.finished_wrong_seq
puts ''
Fuzzer::Fuzzer.wrong_seq
puts ''
Fuzzer::Fuzzer.wrong_finished
puts ''
# Fuzzer::Fuzzer.cookie_test
# Fuzzer::Fuzzer.after_cookie_test
# Fuzzer::Fuzzer.server_explode_test
