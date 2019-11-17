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
require 'acme/pki/version'

module Acme
  class PKI
    include Information

    if ENV['ACME_STAGING']
      puts 'Using Let\'s Encrypt ACME staging'.colorize :yellow
      ENV['ACME_ENDPOINT']    = 'https://acme-staging-v02.api.letsencrypt.org/directory'
      ENV['ACME_ACCOUNT_KEY'] = 'account-staging'
    end
    DEFAULT_ENDPOINT         = ENV['ACME_ENDPOINT'] || 'https://acme-v02.api.letsencrypt.org/directory'
    DEFAULT_DIRECTORY        = ENV['ACME_DIRECTORY'] || Dir.pwd
    DEFAULT_ACCOUNT_KEY      = ENV['ACME_ACCOUNT_KEY'] || 'account'
    DEFAULT_ACCOUNT_KEY_TYPE = [:rsa, 4096].freeze
    DEFAULT_KEY_TYPE         = [:ecc, 'prime256v1'].freeze
    DEFAULT_RENEW_DURATION   = 60 * 60 * 24 * 30 # 1 month

    def initialize(directory: DEFAULT_DIRECTORY, account_key: DEFAULT_ACCOUNT_KEY, endpoint: DEFAULT_ENDPOINT)
      @directory        = directory
      @challenge_dir    = ENV['ACME_CHALLENGE'] || File.join(@directory, 'acme-challenge')
      @account_key_file = self.key DEFAULT_ACCOUNT_KEY, 'key'
      @account_key      = if File.exists? @account_key_file
                            open(@account_key_file, 'r') { |f| OpenSSL::PKey.read f }
                          else
                            nil
                          end
      @endpoint         = endpoint
    end

    def key(name, extension = 'pem')
      self.file name, extension
    end

    def csr(name)
      self.file name, 'csr'
    end

    def crt(name)
      self.file name, 'crt'
    end

    def register(mail)
      @account_key_file, @account_key = self.generate_key DEFAULT_ACCOUNT_KEY, DEFAULT_ACCOUNT_KEY_TYPE, 'key'
      tos                             = self.client.meta['termsOfService']
      $stdout.print "Are you agree with Let's Encrypt terms of service available at #{tos}? [yN] "
      $stdout.flush
      accept = $stdin.gets.chomp.downcase == 'y'
      exit unless accept
      self.process("Registering account key #{@account_key_file}") do
        self.client.new_account contact: "mailto:#{mail}", terms_of_service_agreed: accept
      end
    end

    def generate_key(name, type = DEFAULT_KEY_TYPE, extension = 'pem')
      key_file   = self.key name, extension
      type, size = type

      log = case type
            when :rsa
              "RSA #{size} bits"
            when :ecc
              "ECC #{size} curve"
            end

      key = self.process "Generating #{log} private key into #{key_file}" do
        key = case type
              when :rsa
                OpenSSL::PKey::RSA.new size
              when :ecc
                OpenSSL::PKey::EC.new(size).generate_key
              end
        open(key_file, 'w') { |f| f.write key.to_pem }
        key
      end
      self.key_info key
      [key_file, key]
    end

    def generate_csr(csr, domains: [], key: nil)
      key      = csr unless key
      domains  = [csr, *domains].collect { |d| SimpleIDN.to_ascii d }
      csr_file = self.csr csr
      key_file = self.key key

      self.generate_key key unless File.exist? key_file

      self.process "Generating CSR for #{domains.join ', '} with key #{key_file} into #{csr_file}" do
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
      self.generate_csr short_csr unless File.exist? csr
      self.internal_generate_crt crt, csr: csr
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

      self.internal_generate_crt crt, csr: csr
      true
    end

    def client
      unless @account_key
        puts 'No account key available'.colorize :yellow
        puts 'Please register yourself before'.colorize :red
        exit -1
      end
      @client ||= Acme::Client.new private_key: @account_key, directory: @endpoint
    end

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

    def file(name, extension = nil)
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

    def authorize(authorization)
      domain    = authorization.domain
      challenge = authorization.http
      status    = challenge.status
      if status == 'valid'
        puts "Domain #{domain.colorize :green} already authorized"
        return
      end
      puts "Authorizing domain #{domain.colorize :yellow} (current status: #{status.colorize :yellow})"

      unless Dir.exists? @challenge_dir
        self.process "Creating directory #{@challenge_dir}" do
          FileUtils.mkdir_p @challenge_dir
        end
      end

      filename = challenge.token
      file     = File.join @challenge_dir, filename
      content  = challenge.file_content
      self.process "Writing challenge for #{domain.colorize :yellow} into #{file.colorize :yellow}" do
        File.write file, content
      end

      url = "http://#{domain}/.well-known/acme-challenge/#{filename}"
      self.process "Test challenge for #{url.colorize :yellow}" do
        response = begin
          Faraday.new do |conn|
            conn.use FaradayMiddleware::FollowRedirects
            conn.adapter Faraday.default_adapter
          end.get url
        rescue => e
          raise Exception, e.message
        end
        raise Exception, "Got response code #{response.status.to_s.colorize :red}" unless response.success?
        real_content = response.body
        raise Exception, "Got #{real_content.colorize :red}, expected #{content.colorize :green}" unless real_content == content
      end

      self.process "Authorizing domain #{domain.colorize :yellow}" do
        challenge.request_validation
        status = nil
        60.times do
          sleep 1
          challenge.reload
          status = challenge.status
          break if status != 'pending'
        end

        raise Exception, "Got status #{status.colorize :red} instead of valid" unless status == 'valid'
      end

      File.unlink file
    end

    def internal_generate_crt(crt, csr: nil)
      csr      = crt unless csr
      csr_file = csr
      csr      = OpenSSL::X509::Request.new File.read csr
      domains  = self.domains csr

      order = client.new_order identifiers: domains
      order.authorizations.each { |a| self.authorize a }

      crt = self.process "Generating CRT #{crt} from CSR #{csr_file}" do
        order.finalize csr: csr
        certificate = order.certificate
        File.write crt, certificate
        OpenSSL::X509::Certificate.new certificate
      end

      self.certifificate_info crt
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
