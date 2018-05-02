require_relative "spec_helper.rb"

describe "mod_proxy_jwt_auth" do
  before :all do
    SpecHelpers.wait_ready
  end

  it "is disabled by default" do
    response = SpecHelpers::TestRequest.new("/defaults")
    expect(response.has_bearer_token?).to be_falsy
  end

  it "can be enabled" do
    response = SpecHelpers::TestRequest.new("/enabled")
    expect(response.has_bearer_token?).to be_truthy
  end

  it 'uses the "NONE" algorithm by default' do
    response = SpecHelpers::TestRequest.new("/enabled")
    response.decode
    expect(response.headers["alg"]).to eql("none")
  end

  it "Returns the testvar1 claim from the global config" do
    response = SpecHelpers::TestRequest.new("/enabled")
    response.decode
    expect(response.payload["testvar1"]).to eql("OneValue")
  end

  describe "Token Timing" do
    let(:response) do
      response = SpecHelpers::TestRequest.new("/enabled")
      response.decode
      response
    end

    it "returns a token issued within the last second" do
      delta = Time.now.to_f - response.payload["iat"]
      expect(delta).to be > 0
      expect(delta).to be < 1.0
    end

    it "returns a token valid at issue time" do
      expect(response.payload["nbf"]).to eql(response.payload["iat"])
    end

    it "has a 30 second expiration by default" do
      expect(response.payload["exp"] - response.payload["iat"]).to eql(30)
    end

    it "allows the expiration to be tuned" do
      response = SpecHelpers::TestRequest.new("/token_duration")
      response.decode
      expect(response.payload["exp"] - response.payload["iat"]).to eql(90)
    end
  end

  describe "Claim Mapping" do
    describe "with AllowMissing Enabled" do
      it "returns only testvar1 with no other maps defined" do
        response = SpecHelpers::TestRequest.new("/claim_map/missing_enabled/without_testvar2")
        response.decode
        expect(response.payload["testvar1"]).to eql("OneValue")
        expect(response.payload).to_not include("testvar2")
        expect(response.payload).to_not include("testvar3")
      end

      it "returns testvar1 and testvar2 with testvar2 map defined" do
        response = SpecHelpers::TestRequest.new("/claim_map/missing_enabled/with_testvar2")
        response.decode
        expect(response.payload["testvar1"]).to eql("OneValue")
        expect(response.payload["testvar2"]).to eql("TwoValue")
        expect(response.payload).to_not include("testvar3")
      end

      it "returns testvar1, and empty testvar3 with testvar3 map defined" do
        response = SpecHelpers::TestRequest.new("/claim_map/missing_enabled/with_testvar3")
        response.decode
        expect(response.payload["testvar1"]).to eql("OneValue")
        expect(response.payload).to_not include("testvar2")
        expect(response.payload["testvar3"]).to eql("")
      end
    end

    describe "without AllowMissing Enabled" do
      it "returns only testvar1 with no other maps defined" do
        response = SpecHelpers::TestRequest.new("/claim_map/missing_disabled/without_testvar2")
        response.decode
        expect(response.payload["testvar1"]).to eql("OneValue")
        expect(response.payload).to_not include("testvar2")
        expect(response.payload).to_not include("testvar3")
      end

      it "returns testvar1 and testvar2 with testvar2 map defined" do
        response = SpecHelpers::TestRequest.new("/claim_map/missing_disabled/with_testvar2")
        response.decode
        expect(response.payload["testvar1"]).to eql("OneValue")
        expect(response.payload["testvar2"]).to eql("TwoValue")
        expect(response.payload).to_not include("testvar3")
      end

      it "returns INTERNAL SERVER ERROR with testvar3 map defined" do
        response = SpecHelpers::TestRequest.new("/claim_map/missing_disabled/with_testvar3")
        expect(response.http_code).to eql(500)
      end
    end
  end

  describe "JWT Algorithms" do
    raise("No Algorithms defined") if ModuleTestSuite::ALGORITHMS.empty?
    ModuleTestSuite::ALGORITHMS.keys.each do |algorithm|
      it "supports the #{algorithm} algorithm" do
        response = SpecHelpers::TestRequest.new("/algorithms/#{algorithm}")
        expect { response.decode(algorithm) }.to_not raise_exception
        expect(response.headers["alg"].upcase).to eql(algorithm)
        expect(response.payload["testvar1"]).to eql("OneValue")
      end
    end
  end

  describe "Header name" do
    it "can be changed" do
      response = SpecHelpers::TestRequest.new("/header_name")
      expect(response.has_bearer_token?).to be_falsy
      response = SpecHelpers::TestRequest.new("/header_name", "ProxyAuthorization")
      expect { response.decode }.to_not raise_exception
    end
  end
end
