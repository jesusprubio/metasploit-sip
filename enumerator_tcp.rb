##
# This is a modification of Metasploit enumerator_tcp.rb file.
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'SIP Username Enumerator (TCP)',
			'Version'     => '$Revision: 0 $',
			'Description' => 'Scan for numeric username/extensions using common requests',
			'Author'      =>
				[
					'et',
                    'Jesus Perez <jesus.perez[at]quobis.com>'
                ],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptInt.new('MINEXT',   [true, 'Starting extension', 100]),
			OptInt.new('MAXEXT',   [true, 'Ending extension', 999]),
			OptInt.new('PADLEN',   [true, 'Cero padding maximum length', 3]),
			OptEnum.new('METHOD',  [true, 'Enumeration method', 'REGISTER', ['OPTIONS', 'REGISTER', 'INVITE']]),
			Opt::RPORT(5060)
		], self.class)
	end


	# Operate on a single system at a time
	def run_host(ip)

		connect

		begin
			idx  = 0
			mini = datastore['MINEXT']
			maxi = datastore['MAXEXT']

			for i in (mini..maxi)
				testext = padnum(i,datastore['PADLEN'])
				shost = Rex::Socket.source_address(ip)
				# dirty workarround, we should use local port, not remote
				src = "#{shost}:#{datastore['RPORT']}"
				to_ext = 100 + rand(899)
				data = create_probe(datastore['METHOD'], ip, src, testext, to_ext, 'UDP')			
				begin
					sock.put(data)
					res = sock.get_once(-1, 5)
					parse_reply(res,datastore['METHOD']) if res
				rescue ::Interrupt
					raise $!
				rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
					nil
				end
			end
		rescue ::EOFError
		rescue ::Interrupt
			raise $!
		ensure
			disconnect
		end
	end

	#
	# The response parsers
	#
	def parse_reply(resp,meth)

		repcode = ''
		agent  = ''
		verbs = ''
		serv  = ''
		prox  = ''

		if(resp =~ /^To\:\s*(.*)$/mi)
			testn = "#{$1.strip}".split(';')[0]
		end

		case resp
		when 401, 407
			print_status("Found user: #{testn} [Auth]")
			#Add Report
			report_note(
				:host	=> rhost,
				:proto	=> 'sip',
				:port	=> rport,
				:type	=> "Found user: #{testn} [Auth]",
				:data	=> "Found user: #{testn} [Auth]"
			)
		when 200
			print_status("Found user: #{testn} [Open]")
			#Add Report
			report_note(
				:host	=> rhost,
				:proto	=> 'sip',
				:port	=> rport,
				:type	=> "Found user: #{testn} [Open]",
				:data	=> "Found user: #{testn} [Open]"
			)
		else
			#print_error("Undefined error code: #{resp.to_i}"
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
