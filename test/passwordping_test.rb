require 'test/unit'
require_relative "../lib/passwordping"
require_relative "../lib/passwordping/errors"

#
# These are actually live tests and require a valid API key and Secret to be set in your environment variables.
# Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
#
class PasswordPingTest < Test::Unit::TestCase
  def test_init
    # make sure init complains if no API key or secret provided
    exception = false
    begin
      PasswordPing::PasswordPing.new()
    rescue PasswordPing::PasswordPingFail => detail
      exception = true
      assert_equal("No API key provided", detail.message)
    end
    assert(exception)

    exception = false
    begin
      PasswordPing::PasswordPing.new(apiKey: get_api_key())
    rescue PasswordPing::PasswordPingFail => detail
      exception = true
      assert_equal("No Secret provided", detail.message)
    end
    assert(exception)
  end

  def test_check_credentials
    passwordping = get_passwordping()
    assert(passwordping.check_credentials('test@passwordping.com', '123456'))
    assert(!passwordping.check_credentials('test@passwordping.com', '123456122'))
  end

  def test_check_password
    passwordping = get_passwordping()
    assert(!passwordping.check_password("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd"))
    assert(passwordping.check_password("123456"))
  end

  def test_get_exposures_for_user
    passwordping = get_passwordping()

    result = passwordping.get_exposures_for_user("@@bogus-username@@")
    assert_equal(0, result.count)
    assert_equal(0, result.exposures.length)

    result = passwordping.get_exposures_for_user("eicar")
    assert_equal(4, result.count)
    assert_equal(4, result.exposures.length)
    assert_equal(["5820469ffdb8780510b329cc", "58258f5efdb8780be88c2c5d", "582a8e51fdb87806acc426ff", "583d2f9e1395c81f4cfa3479"], result.exposures)
  end

  def test_get_exposure_details
    passwordping = get_passwordping()

    result = passwordping.get_exposure_details("111111111111111111111111")
    assert_equal(nil, result)

    result = passwordping.get_exposure_details("5820469ffdb8780510b329cc")
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

  private
    def get_passwordping
      return PasswordPing::PasswordPing.new(apiKey: get_api_key(), secret: get_api_secret())
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
