require 'acme/client'
require 'base64'
require 'colorize'
require 'digest'
require 'faraday_middleware'
require 'openssl'
require 'optparse'
require 'ostruct'
require 'simpleidn'

require 'acme/pki/monkey_patch'
require 'acme/pki/information'

module Acme
	class PKI
		include Information

		DEFAULT_ENDPOINT       = ENV['ACME_ENDPOINT'] || 'https://acme-v01.api.letsencrypt.org/'
		DEFAULT_ACCOUNT_KEY    = ENV['ACME_ACCOUNT_KEY'] || 'account.key'
		DEFAULT_KEY            = [:ecc, 'secp384r1']
		#DEFAULT_KEY            = [:rsa, 4096]
		DEFAULT_RENEW_DURATION = 60*60*24*30 # 1 month

		def initialize(directory: Dir.pwd, account_key: DEFAULT_ACCOUNT_KEY, endpoint: DEFAULT_ENDPOINT)
			@directory       = directory
			account_key_file = File.join @directory, account_key
			@challenge_dir   = ENV['ACME_CHALLENGE'] || File.join(@directory, 'acme-challenge')

			mail = ENV['ACME_MAIL_REGISTRATION']
			register    = false
			account_key = if File.exists? account_key_file
							  open(account_key_file, 'r') { |f| OpenSSL::PKey.read f }
						  else
							  unless mail
								  puts 'No registration key found.'.colorize :yellow
								  puts 'Please define ACME_MAIL_REGISTRATION environment variable for registration'.colorize :red
								  exit -1
							  end
							  process("Generating RSA 4096 bits account key into #{account_key_file}") do
								  register    = true
								  account_key = OpenSSL::PKey::RSA.new 4096
								  File.write account_key_file, account_key.to_pem
								  account_key
							  end
						  end

			@client = Acme::Client.new private_key: account_key, endpoint: endpoint

			if register
				process("Registering account key #{account_key_file}") do
					registration = @client.register contact: "mailto:#{mail}"
					registration.agree_terms
				end
			end
		end

		def key(name)
			file name, 'pem'
		end

		def csr(name)
			file name, 'csr'
		end

		def crt(name)
			file name, 'crt'
		end

		def generate_key(name, type: DEFAULT_KEY)
			key_file   = self.key name
			type, size = type

			key = case type
					  when :rsa
						  process "Generating RSA #{size} bits private key into #{key_file}" do
							  key = OpenSSL::PKey::RSA.new size
							  open(key_file, 'w') { |f| f.write key.to_pem }
							  key
						  end
					  when :ecc
						  process "Generating ECC #{size} curve private key into #{key_file}" do
							  key = OpenSSL::PKey::EC.new(size).generate_key
							  open(key_file, 'w') { |f| f.write key.to_pem }
							  key
						  end
				  end

			key_info key
		end

		def generate_csr(csr, domains: [], key: nil)
			key      = csr unless key
			domains  = [csr, *domains].collect { |d| SimpleIDN.to_ascii d }
			csr_file = self.csr csr
			key_file = self.key key

			generate_key key unless File.exist? key_file

			process "Generating CSR for #{domains.join ', '} with key #{key_file} into #{csr_file}" do
				key_file    = open(key_file, 'r') { |f| OpenSSL::PKey.read f }
				csr         = OpenSSL::X509::Request.new
				csr.subject = OpenSSL::X509::Name.parse "/CN=#{domains.first}"

				public_key     = case key_file
									 when OpenSSL::PKey::EC
										 curve             = key_file.group.curve_name
										 public            = OpenSSL::PKey::EC.new curve
										 public.public_key = key_file.public_key
										 public
									 else
										 key_file.public_key
								 end
				csr.public_key = public_key

				factory    = OpenSSL::X509::ExtensionFactory.new
				extensions = []
				#extensions << factory.create_extension('basicConstraints', 'CA:FALSE', true)
				extensions << factory.create_extension('keyUsage', 'digitalSignature,nonRepudiation,keyEncipherment')
				extensions << factory.create_extension('subjectAltName', domains.collect { |d| "DNS:#{d}" }.join(', '))

				extensions = OpenSSL::ASN1::Sequence extensions
				extensions = OpenSSL::ASN1::Set [extensions]
				csr.add_attribute OpenSSL::X509::Attribute.new 'extReq', extensions

				csr.sign key_file, OpenSSL::Digest::SHA512.new
				open(csr_file, 'w') { |f| f.write csr.to_pem }
			end
		end

		def generate_crt(crt, csr: nil)
			csr       = crt unless csr
			short_csr = csr
			crt       = self.crt crt
			csr       = self.csr csr
			generate_csr short_csr unless File.exist? csr
			internal_generate_crt crt, csr: csr
		end

		def renew(crt, csr: nil, duration: DEFAULT_RENEW_DURATION)
			csr = crt unless csr
			crt = self.crt crt
			csr = self.csr csr
			puts "Renewing #{crt} CRT from #{csr} CSR"

			if File.exists? crt
				x509  = OpenSSL::X509::Certificate.new File.read crt
				delay = x509.not_after - Time.now
				if delay > duration
					puts "No need to renew (#{humanize delay})"
					return false
				end
			end

			internal_generate_crt crt, csr: csr
			true
		end

		private
		def process(line, io: STDOUT)
			io.print "#{line}..."
			io.flush

			result = yield

			io.puts " [#{'OK'.colorize :green}]"

			result
		rescue Exception
			io.puts " [#{'KO'.colorize :red}]"
			raise
		end

		def file(name, extension=nil)
			return nil unless name
			name = name.split('.').reverse.join('.')
			name = "#{name}.#{extension}" if extension
			File.join @directory, name
		end

		def domains(csr)
			domains = []

			cn = csr.subject.to_a.first { |n, _, _| n == 'CN' }
			domains << cn[1] if cn

			attribute = csr.attributes.detect { |a| %w(extReq msExtReq).include? a.oid }
			if attribute
				set  = OpenSSL::ASN1.decode attribute.value
				seq  = set.value.first
				sans = seq.value.collect { |s| OpenSSL::X509::Extension.new(s).to_a }
							   .detect { |e| e.first == 'subjectAltName' }
				if sans
					sans = sans[1]
					sans = sans.split(/\s*,\s*/)
								   .collect { |s| s.split /\s*:\s*/ }
								   .select { |t, _| t == 'DNS' }
								   .collect { |_, v| v }
					domains.concat sans
				end
			end

			domains.uniq
		end

		def authorize(domain)
			authorization = @client.authorize domain: domain
			challenge     = authorization.http01

			unless Dir.exists? @challenge_dir
				process "Creating directory #{@challenge_dir}" do
					FileUtils.mkdir_p @challenge_dir
				end
			end

			filename = challenge.token
			file     = File.join @challenge_dir, filename
			content  = challenge.file_content
			process "Writing challenge for #{domain} into #{file}" do
				File.write file, content
			end

			url = "http://#{domain}/.well-known/acme-challenge/#{filename}"
			process "Test challenge for #{url}" do
				response = Faraday.new do |conn|
					conn.use FaradayMiddleware::FollowRedirects
					conn.adapter Faraday.default_adapter
				end.get url
				raise Exception, "Got response code #{response.status}" unless response.success?
				real_content = response.body
				raise Exception, "Got #{real_content}, expected #{content}" unless real_content == content
			end

			process "Authorizing domain #{domain}" do
				challenge.request_verification
				status = nil
				60.times do
					sleep 1
					status = challenge.verify_status
					break if status != 'pending'
				end

				raise Exception, "Got status #{status} instead of valid" unless status == 'valid'
			end
		end

		def internal_generate_crt(crt, csr: nil)
			csr      = crt unless csr
			csr_file = csr
			csr      = OpenSSL::X509::Request.new File.read csr
			domains  = domains csr

			domains.each { |d| authorize d }

			crt = process "Generating CRT #{crt} from CSR #{csr_file}" do
				certificate = @client.new_certificate csr
				File.write crt, certificate.fullchain_to_pem
				OpenSSL::X509::Certificate.new certificate.to_pem
			end

			certifificate_info crt
		end

		def humanize(secs)
			[[60, :seconds], [60, :minutes], [24, :hours], [30, :days], [12, :months]].map { |count, name|
				if secs > 0
					secs, n = secs.divmod count
					"#{n.to_i} #{name}"
				end
			}.compact.reverse.join(' ')
		end
	end
end
