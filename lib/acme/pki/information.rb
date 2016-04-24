require 'fileutils'

module Acme
	class PKI
		module Information
			def key_info(key, tab: 0)
				key = open(key, 'r') { |f| OpenSSL::PKey.read f } unless key.is_a? OpenSSL::PKey::PKey
				der = key.to_der

				fingerprint der, tab: tab

				hpkp = Digest::SHA256.digest der
				hpkp = Base64.encode64(hpkp).strip
				title 'HPKP', tab: tab
				puts "\t" * (tab+1) + "Public-Key-Pins \"max-age=5184000; pin-sha256=\\\"#{hpkp}\\\";".colorize(:blue)

				tlsa = Digest::SHA512.hexdigest der
				title 'TLSA', tab: tab
				puts "\t" * (tab+1) + "TLSA 1 1 2 #{tlsa}".colorize(:blue)
			end

			def certifificate_info(crt)
				title 'Subject'
				puts "\t#{crt.subject}"
				title 'Issuer'
				puts "\t#{crt.issuer}"

				der = crt.to_der

				fingerprint der

				hpkp = Digest::SHA256.digest der
				hpkp = Base64.encode64(hpkp).strip
				title 'HPKP'
				puts "\tPublic-Key-Pins \"max-age=5184000; pin-sha256=\\\"#{hpkp}\\\";".colorize(:blue)

				tlsa = Digest::SHA512.hexdigest der
				title 'TLSA'
				puts "\tTLSA 1 0 2 #{tlsa}".colorize(:blue)

				title 'Public key'
				key_info crt.public_key, tab: 1
			end

			def chain_info(chain)
				chain = File.read(chain).split('-----BEGIN CERTIFICATE-----')
								.reject { |s| s.empty? }
								.collect { |s| '-----BEGIN CERTIFICATE-----' + s }
								.collect { |s| OpenSSL::X509::Certificate.new s }
				loop do
					last   = chain.last
					issuer = last.issuer
					break if last.subject == issuer
					# This is not a root, fetch the issuer

					aia = last.extensions.detect { |e| e.oid == 'authorityInfoAccess' }
					break unless aia

					uri = aia.value.split("\n").find { |s| s.start_with? 'CA Issuers - URI:' }
								  .sub /^CA Issuers - URI:/, ''
					puts "Fetch certificate #{issuer} from #{uri}"
					file = Digest::MD5.hexdigest uri
					file = file File.join 'cache', file
					dir = File.dirname file
					FileUtils.mkpath dir unless Dir.exist? dir
					crt  = if File.exist? file
							   open(file, 'r') { |f| OpenSSL::X509::Certificate.new f }
						   else
							   crt = Faraday.get uri
							   break unless crt.success?
							   crt = crt.body

							   crt = begin
								   OpenSSL::X509::Certificate.new crt
							   rescue
								   pkcs7 = OpenSSL::PKCS7.new crt
								   pkcs7.certificates.first
							   end

							   File.write file, crt.to_pem
							   crt
						   end

					subject = crt.subject
					puts "Warning : expecting #{issuer}, get #{subject}".colorize :magenta unless subject == issuer

					chain << crt
				end

				chain.each do |c|
					certifificate_info c
					puts ''
				end
			end

			private
			def title(title, tab: 0)
				puts "\t" * tab + title.colorize(:red) + ' :'
			end

			def fingerprint(der, tab: 0)
				der = der.to_der if der.respond_to? :to_der

				title 'Fingerprint', tab: tab
				%w(SHA512 SHA256 SHA1).each do |h|
					fp = Digest.const_get(h).hexdigest(der).scan(/../).join ':'
					puts "\t" * (tab+1) + h.colorize(:yellow) + ' ' + fp.colorize(:blue)
				end
			end
		end
	end
end
