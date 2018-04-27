require "openssl"

module ModuleTestSuite
  ALGORITHMS = {
    "NONE"  => { :type => "NONE" },
    "HS256" => { :type => "HMAC" },
    "HS384" => { :type => "HMAC" },
    "HS512" => { :type => "HMAC" },
    "RS256" => { :type => "RSA" },
    "RS384" => { :type => "RSA" },
    "RS512" => { :type => "RSA" },
    "ES256" => { :type => "ECDSA" },
    "ES384" => { :type => "ECDSA" },
    "ES512" => { :type => "ECDSA" }
  }.freeze

  module Keys
    def self.private_key_filename(algorithm)
      return nil if algorithm == "NONE"
      "/test_files/keys/test_#{algorithm}_private_key.pem"
    end

    def self.public_key_filename(algorithm)
      return nil if algorithm == "NONE"
      "/test_files/keys/test_#{algorithm}_public_key.pem"
    end

    def self.save_keys
      ModuleTestSuite::ALGORITHMS.keys.each do |algorithm|
        next if algorithm == "NONE"
        private_key, public_key = _generate_keypair(algorithm)

        File.write(private_key_filename(algorithm), private_key)
        File.write(public_key_filename(algorithm), public_key)
      end
    end

    def self.load_public_key(algorithm)
      return nil if algorithm == "NONE"
      contents = File.read(public_key_filename(algorithm))

      # Return object types appropriate for JWT.decode
      case ModuleTestSuite::ALGORITHMS[algorithm][:type]
      when "HMAC"
        return contents
      when "RSA"
        return OpenSSL::PKey::RSA.new(contents)
      when "ECDSA"
        return OpenSSL::PKey::EC.new(contents)
      end

      raise("Unknown algorithm algorithm")
    end

    def self._generate_keypair(algorithm)
      case ModuleTestSuite::ALGORITHMS[algorithm][:type]
      when "HMAC"
        secret = (0...50).map { ("a".."z").to_a[rand(26)] }.join
        return secret, secret
      when "RSA"
        key = OpenSSL::PKey::RSA.generate 2048
        return key.to_s, key.public_key.to_s
      when "ECDSA"
        ecdsa_key = OpenSSL::PKey::EC.new case algorithm
                                          when "ES256"
                                            "prime256v1"
                                          when "ES384"
                                            "secp384r1"
                                          when "ES512"
                                            "secp521r1"
                                          end

        ecdsa_key.generate_key
        ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
        ecdsa_public.private_key = nil
        return ecdsa_key.to_pem, ecdsa_public.to_pem
      end

      raise("Unknown algorithm type #{type}")
    end
    private_class_method :_generate_keypair
  end
end
