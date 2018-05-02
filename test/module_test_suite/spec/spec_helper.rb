require "httparty"
require "jwt"

require_relative "../lib/algorithms.rb"

module SpecHelpers
  def self.wait_ready
    30.times do |c|
      begin
        HTTParty.get("http://httpd/")
        return # rubocop: disable Lint/NonLocalExitFromIterator
      rescue StandardError => exc
        puts "HTTPd not ready after #{c} seconds: #{exc}"
      end
      sleep(1)
    end
    raise("HTTPd failed to come up")
  end

  class TestRequest
    attr_reader :raw_response, :authorization_type, :b64_token, :token

    def initialize(path, header_name = "Authorization")
      @raw_response = HTTParty.get("http://httpd/#{path}")
      return unless http_code == 200
      # header_name.upcase is due to Sinatra upcasing the headers.
      @authorization_type, @b64_token = @raw_response["@env"].fetch("HTTP_#{header_name.upcase}", "").split(" ")
    end

    def http_code
      @raw_response.code
    end

    def has_bearer_token?
      @authorization_type == "Bearer"
    end

    def decode(algorithm = "NONE")
      return nil unless has_bearer_token?
      key = ModuleTestSuite::Keys.load_public_key(algorithm)
      @token = JWT.decode(@b64_token, key, !key.nil?, :algorithm => algorithm)
    end

    def headers
      return {} unless @token
      @token[1]
    end

    def payload
      return {} unless @token
      @token[0]
    end
  end
end
