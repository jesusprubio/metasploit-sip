##
# This is a modification of Metasploit options.rb file.
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

    include Msf::Auxiliary::Report
    include Msf::Auxiliary::Scanner

    def initialize
        super(
            'Name'        => 'SIP Endpoint Scanner (UDP)',
            'Version'     => '$Revision: 0 $',
            'Description' => 'Scan for SIP devices using common requests',
            'Author'      =>
                [
                    'hdm',
                    'Jesus Perez <jesus.perez[at]quobis.com>'
                ],
            'License'     => MSF_LICENSE
        )

        register_options(
        [
            OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
            OptString.new('TO',   [ false, "The destination username to probe at each host", "nobody"]),
            OptEnum.new('METHOD',  [true, 'Flood method', 'OPTIONS', ['OPTIONS', 'INVITE', 'REGISTER', 'ACK', 'OK', 'BYE', 'TRYING', 'RINGING']]),
            Opt::RPORT(5060),
            Opt::CHOST,
            Opt::CPORT(5060)
        ], self.class)
    end


    # Define our batch size
    def run_batch_size
        datastore['BATCHSIZE'].to_i
    end

    # Operate on an entire batch of hosts at once
    def run_batch(batch)

        begin
            udp_sock = nil
            idx = 0

            # Create an unbound UDP socket if no CHOST is specified, otherwise
            # create a UDP socket bound to CHOST (in order to avail of pivoting)
            udp_sock = Rex::Socket::Udp.create(
                {
                    'LocalHost' => datastore['CHOST'] || nil,
                    'LocalPort' => datastore['CPORT'].to_i,
                    'Context' => {'Msf' => framework, 'MsfExploit' => self}
                }
            )
            add_socket(udp_sock)

            batch.each do |ip|
				testext = 100 + rand(899)
                shost = Rex::Socket.source_address(ip)
                src = "#{shost}:#{datastore['CPORT']}"
                to_ext = 100 + rand(899)
                data = create_probe(datastore['METHOD'], ip, src, testext, to_ext, 'UDP')
                
                begin
                    udp_sock.sendto(data, ip, datastore['RPORT'].to_i, 0)
                rescue ::Interrupt
                    raise $!
                rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
                    nil
                end

                if (idx % 10 == 0)
                    while (r = udp_sock.recvfrom(65535, 0.01) and r[1])
                        parse_reply(r)
                    end
                end

                idx += 1
            end

            while (r = udp_sock.recvfrom(65535, 3) and r[1])
                parse_reply(r)
            end

        rescue ::Interrupt
            raise $!
        rescue ::Exception => e
            print_error("Unknown error: #{e.class} #{e}")
        ensure
            udp_sock.close if udp_sock
        end
    end

    #
    # The response parsers
    #
    def parse_reply(pkt)

        return if not pkt[1]

        if(pkt[1] =~ /^::ffff:/)
            pkt[1] = pkt[1].sub(/^::ffff:/, '')
        end

        resp  = pkt[0].split(/\s+/)[1]
        agent = ''
        verbs = ''
        serv  = ''
        prox  = ''

        if(pkt[0] =~ /^User-Agent:\s*(.*)$/i)
            agent = "agent='#{$1.strip}' "
        end

        if(pkt[0] =~ /^Allow:\s+(.*)$/i)
            verbs = "verbs='#{$1.strip}' "
        end

        if(pkt[0] =~ /^Server:\s+(.*)$/)
            serv = "server='#{$1.strip}' "
        end

        if(pkt[0] =~ /^Proxy-Require:\s+(.*)$/)
            serv = "proxy-required='#{$1.strip}' "
        end

        print_status("#{pkt[1]} #{resp} #{agent}#{serv}#{prox}#{verbs}")

        report_service(
            :host   => pkt[1],
            :port   => pkt[2],
            :proto  => 'udp',
            :name   => 'sip'
        )

        if(not agent.empty?)
            report_note(
                :host   => pkt[1],
                :type  => 'sip_useragent',
                :data   => agent
            )
        end
    end

    # SIP requests creator
    def create_probe(meth, realm, shost, from_ext, to_ext, transport)
        from_tag = "%.8x" % rand(0x100000000)
        to_tag = "%.8x" % rand(0x100000000)
        branch_pad = "%.7x" % rand(0x10000000)
        #ext = rand(999)
        from_uri = "sip:#{from_ext}@#{realm}"
        target_uri = "sip:#{realm}"
        #cseq = rand(99999)
        cseq = 1

        call_id = 10000000000 + rand(89999999999)
        chain = "%.16x" % rand(0x10000000000000000)
        call_id_reg = "#{call_id}@#{chain}" 
        to_uri = "sip:#{to_ext}@#{realm}"
        session_id = 1000000000 + rand(8999999999)

        case meth
            when "REGISTER"
                data  = "#{meth} #{target_uri} SIP/2.0\r\n"
            when "OPTIONS", "INVITE", "ACK", "BYE"
                data  = "#{meth} #{to_uri} SIP/2.0\r\n"
            when "OK"
                data = "SIP/2.0 200 OK\r\n"
            when "TRYING"
                data = "SIP/2.0 100 Trying\r\n"
            when "RINGING"
                data = "SIP/2.0 180 Ringing\r\n"
        end
        data << "Via: SIP/2.0/#{transport} #{shost};branch=z9hG4bK#{branch_pad}\r\n"
        if (meth == "OK" or meth == "TRYING" or meth == "RINGING")
            data << " ;received = #{shost}\r\n"
        end
        if (meth == "REGISTER" or meth == "OPTIONS" or meth == "INVITE" or meth == "BYE" or meth == "ACK")
            data << "Max-Forwards: 70\r\n"
        end
        data << "From: #{from_ext} <#{from_uri}>;tag=#{from_tag}\r\n"
        case meth
            when "REGISTER"
                data << "To: #{from_ext} <#{from_uri}>\r\n"
            when "ACK", "BYE", "OK", "RINGING", "TRYING", "OPTIONS", "INVITE"
                data << "To: #{to_ext} <#{to_uri}>;tag=#{to_tag}\r\n"
        end
        case meth
            when "REGISTER"
				data << "Call-ID: #{call_id}@#{call_id_reg}\r\n"
            when "ACK", "BYE", "OK", "RINGING", "TRYING", "OPTIONS", "INVITE"
				data << "Call-ID: #{call_id}\r\n"
        end
        case meth
            when "REGISTER", "INVITE", "ACK", "BYE", "OPTIONS"
                data << "CSeq: #{cseq} #{meth}\r\n"
            when "OK", "TRYING", "RINGING"
                data << "CSeq: #{cseq} INVITE\r\n"
        end
        case meth
            when "REGISTER", "OPTIONS"
                data << "Contact: <#{from_uri}>\r\n"
            when "OK", "RINGING", "INVITE"
                data << "Contact: <#{to_uri};transport=#{transport.downcase}>\r\n"
        end
        if (meth == "OPTIONS")
            data << "Accept: application/sdp\r\n"
        end
        if (meth == "INVITE" or meth == "OK")
            data << "Content-Type: application/sdp\r\n"
            sdp = "v=0\r\n"
            sdp << "o=#{from_ext} #{session_id} #{session_id} IN IP4 #{shost}\r\n"
            sdp << "s=-\r\n"
            sdp << "c=IN IP4 #{shost}\r\n"
            sdp << "t=0 0\r\n"
            sdp << "m=audio 49172 RTP/AVP 0\r\n"
            sdp << "a=rtpmap:0 PCMU/8000\r\n"
        end
        case meth
            when "REGISTER", "OPTIONS", "ACK", "BYE", "TRYING", "RINGING"
                data << "Content-Length: 0\r\n"
            when "INVITE", "OK"
                data << "Content-Length: #{sdp.size}\r\n"
        end
        data << "\r\n"
        if (meth == "INVITE" or meth == "OK")
            data << sdp
        end

        return data
    end

    def padnum(num,padding)
        if padding >= num.to_s.length
            ('0'*(padding-num.to_s.length)) << num.to_s
        end
    end
end
