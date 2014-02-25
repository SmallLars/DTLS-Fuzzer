DTLS-Fuzzer
===========

Fuzzer for DTLS. Created at the University of Bremen in the block course "Server Hardening"

**Usage**

In fuzzer.rb are some examples how to use the "do_steps" method. With this method
you can execute the handshake of dtls to the step of your choise. The method will
return all pakets which was exchanged between fuzzer and server and also the next
paket(s) needed to send to continue handshake. So you are able to change all the
parameters of the packet, to start special tests. If already available, the method
will return the keys to. At the moment there is only one ciphersuite supported:
TLS_PSK_WITH_AES_128_CCM_8

**Available steps**
    #
Step | Keys   | send in do_steps           | return in tosend
------------------------------------------------------------------------------------------
   0 | -      |                          - | ClientHello without Cookie
   1 | -      | ClientHello without Cookie | ClientHello with Cookie
   2 | avail. | ClientHello with Cookie    | ClientKeyExchange, ChangeCipherSpec, Finished
   3 | avail. | ClientKeyExchange          | ChangeCipherSpec, Finished
   4 | avail. | ChangeCipherSpec           | Finished
   5 | avail. | Finished                   | ApplicationData
   6 | avail. | ApplicationData            | CloseNotify
   7 | avail. | CloseNotify                | -

                    Fuzzer           Server
                    ------           ------
      ClientHello  (seq=0) ----0--->
                           <-------- (seq=0)  HelloVerifyRequest
      ClientHello  (seq=1) ----1--->
     (mit cookie)
                           <-------- (seq=1)  ServerHello
                           <-------- (seq=2)  ServerKeyExchange
                           <-------- (seq=3)  ServerHelloDone
ClientKeyExchange  (seq=2) ----2--->
 ChangeCipherSpec          ----3--->
         Finished  (seq=3) ----4--->
                           <--------          ChangeCipherSpec
                           <-------- (seq=4)  Finished
 Application Data          ----5--->
                           <--------          Application Data
      CloseNotify          ----6--->
