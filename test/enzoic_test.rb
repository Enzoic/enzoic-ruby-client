require 'test/unit'
require_relative "../lib/enzoic"
require_relative "../lib/enzoic/password_type"
require_relative "../lib/enzoic/errors"

#
# These are actually live tests and require a valid API key and Secret to be set in your environment variables.
# Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
#
class EnzoicTest < Test::Unit::TestCase
  def test_init
    # make sure init complains if no API key or secret provided
    exception = false
    begin
      Enzoic::Enzoic.new()
    rescue Enzoic::EnzoicFail => detail
      exception = true
      assert_equal("No API key provided", detail.message)
    end
    assert(exception)

    exception = false
    begin
      Enzoic::Enzoic.new(apiKey: get_api_key())
    rescue Enzoic::EnzoicFail => detail
      exception = true
      assert_equal("No Secret provided", detail.message)
    end
    assert(exception)
  end

  def test_check_credentials
    enzoic = get_enzoic()
    assert(enzoic.check_credentials('test@passwordping.com', '123456'))
    assert(!enzoic.check_credentials('test@passwordping.com', '123456122'))
  end

  def test_check_password
    enzoic = get_enzoic()
    assert(!enzoic.check_password("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd"))
    assert(enzoic.check_password("123456"))
  end

  def test_get_exposures_for_user
    enzoic = get_enzoic()

    result = enzoic.get_exposures_for_user("@@bogus-username@@")
    assert_equal(0, result.count)
    assert_equal(0, result.exposures.length)

    result = enzoic.get_exposures_for_user("eicar")
    assert_equal(8, result.count)
    assert_equal(8, result.exposures.length)
    assert_equal(["5820469ffdb8780510b329cc",
                 "58258f5efdb8780be88c2c5d",
                 "582a8e51fdb87806acc426ff",
                 "583d2f9e1395c81f4cfa3479",
                 "59ba1aa369644815dcd8683e",
                 "59cae0ce1d75b80e0070957c",
                 "5bc64f5f4eb6d894f09eae70",
                 "5bdcb0944eb6d8a97cfacdff"], result.exposures)
  end

  def test_get_exposure_details
    enzoic = get_enzoic()

    result = enzoic.get_exposure_details("111111111111111111111111")
    assert_equal(nil, result)

    result = enzoic.get_exposure_details("5820469ffdb8780510b329cc")
    assert(result != nil)
    assert_equal("5820469ffdb8780510b329cc", result.id)
    assert_equal("last.fm", result.title)
    assert_equal("Music", result.category)
    assert_equal("2012-03-01T00:00:00.000Z", result.date)
    assert_equal("MD5", result.passwordType)
    assert_equal(["Emails", "Passwords", "Usernames", "Website Activity"], result.exposedData)
    assert_equal(43570999, result.entries)
    assert_equal(1218513, result.domainsAffected)
  end

  def test_calc_password_hash
    enzoic = get_enzoic()

    assert_equal("e10adc3949ba59abbe56e057f20f883e", enzoic.send(:calc_password_hash, Enzoic::PasswordType::MD5, "123456", nil))
    assert_equal("7c4a8d09ca3762af61e59520943dc26494f8941b", enzoic.send(:calc_password_hash, Enzoic::PasswordType::SHA1, "123456", nil))
    assert_equal("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", enzoic.send(:calc_password_hash, Enzoic::PasswordType::SHA256, "123456", nil))
    assert_equal("2e705e174e9df3e2c8aaa30297aa6d74", enzoic.send(:calc_password_hash, Enzoic::PasswordType::IPBoard_MyBB, "123456", ";;!_X"))
    assert_equal("57ce303cdf1ad28944d43454cea38d7a", enzoic.send(:calc_password_hash, Enzoic::PasswordType::VBulletinPre3_8_5, "123456789", "]G@"))
    assert_equal("$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", enzoic.send(:calc_password_hash, Enzoic::PasswordType::BCrypt, "12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"))
    assert_equal("972d361", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CRC32, "123456", nil))
    assert_equal("$H$993WP3hbzy0N22X06wxrCc3800D2p41", enzoic.send(:calc_password_hash, Enzoic::PasswordType::PHPBB3, "123456789", "$H$993WP3hbz"))
    assert_equal("cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm1, "123456", "00new00"))
    assert_equal("579d9ec9d0c3d687aaa91289ac2854e4", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm2, "123456", "123"))
    assert_equal("$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm4, "1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZO"))
    assert_equal("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", enzoic.send(:calc_password_hash, Enzoic::PasswordType::SHA512, "test", nil))
    assert_equal("$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.", enzoic.send(:calc_password_hash, Enzoic::PasswordType::MD5Crypt, "123456", "$1$4d3c09ea"))
  end

  private
    def get_enzoic
      return Enzoic::Enzoic.new(apiKey: get_api_key(), secret: get_api_secret())
    end

    def get_api_key
      # set these env vars to run live tests
      return ENV["PP_API_KEY"]
    end

    def get_api_secret
      # set these env vars to run live tests
      return ENV["PP_API_SECRET"]
    end
end
