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
    assert(enzoic.check_credentials('eicar_2@enzoic.com', '123456'))
    assert(!enzoic.check_credentials('eicar_2@enzoic.com', '123456122'))
    assert(!enzoic.check_credentials('eicar_2@enzoic.com', '123456', DateTime.now))
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
    assert_equal(81967007, result.entries)
    assert_equal(1219053, result.domainsAffected)
  end

  def test_get_passwords_for_user
    enzoic = get_enzoic

    result = enzoic.get_passwords_for_user("@@bogus-username@@")
    assert_nil(result.lastBreachDate)
    assert_equal(0, result.passwords.length)

    result = enzoic.get_passwords_for_user("eicar_0@enzoic.com")
    assert_equal(4, result.passwords.length)
    assert_equal("2022-10-14T07:02:40.000Z", result.lastBreachDate)
    assert_equal(JSON.parse('[
                   {
                     "hashType": 0,
                     "salt": "",
                     "password": "password123",
                     "exposures": ["634908d2e0513eb0788aa0b9", "634908d06715cc1b5b201a1a"]
                   },
                   {
                     "hashType": 0,
                     "salt": "",
                     "password": "g0oD_on3",
                     "exposures": ["634908d2e0513eb0788aa0b9"]
                   },
                   {
                     "hashType": 0,
                     "salt": "",
                     "password": "Easy2no",
                     "exposures": ["634908d26715cc1b5b201a1d"]
                   },
                   {
                     "hashType": 0,
                     "salt": "",
                     "password": "123456",
                     "exposures": ["63490990e0513eb0788aa0d1", "634908d0e0513eb0788aa0b5"]
                   }
                 ]', object_class: OpenStruct), result.passwords)

    # try from account with no permissions
    begin
      enzoic = Enzoic::Enzoic.new(apiKey: ENV["PP_API_KEY_2"], secret: ENV["PP_API_SECRET_2"])
      result = enzoic.get_passwords_for_user("eicar_0@enzoic.com")
      assert_fail_assertion("accounts without permission should get rejected")
    rescue => error
      assert_equal("403 Forbidden", error.message)
    end
  end

  def test_calc_password_hash
    enzoic = get_enzoic

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
    assert_equal("69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm5, "password", "123456"))
    assert_equal("d2bc2f8d09990ebe87c809684fd78c66", enzoic.send(:calc_password_hash, Enzoic::PasswordType::OsCommerce_AEF, "password", "123"))
    assert_equal("X.OPW8uuoq5N.", enzoic.send(:calc_password_hash, Enzoic::PasswordType::DESCrypt, "password", "X."))
    assert_equal("5d2e19393cc5ef67", enzoic.send(:calc_password_hash, Enzoic::PasswordType::MySQLPre4_1, "password", ""))
    assert_equal("*94bdcebe19083ce2a1f959fd02f964c7af4cfc29", enzoic.send(:calc_password_hash, Enzoic::PasswordType::MySQLPost4_1, "test", ""))
    assert_equal("0c9a0dc3dd0b067c016209fd46749c281879069e", enzoic.send(:calc_password_hash, Enzoic::PasswordType::PunBB, "password", "123"))
    assert_equal("cbfdac6008f9cab4083784cbd1874f76618d2a97", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm6, "password", "123"))
    assert_equal("5f4dcc3b5aa765d61d83", enzoic.send(:calc_password_hash, Enzoic::PasswordType::PartialMD5_20, "password", ""))
    assert_equal("696d29e0940a4957748fe3fc9efd22a3", enzoic.send(:calc_password_hash, Enzoic::PasswordType::AVE_DataLife_Diferior, "password", ""))
    assert_equal("md5$c6218$346abd81f2d88b4517446316222f4276", enzoic.send(:calc_password_hash, Enzoic::PasswordType::DjangoMD5, "password", "c6218"))
    assert_equal("sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845", enzoic.send(:calc_password_hash, Enzoic::PasswordType::DjangoSHA1, "password", "c6218"))
    assert_equal("5f4dcc3b5aa765d61d8327deb882c", enzoic.send(:calc_password_hash, Enzoic::PasswordType::PartialMD5_29, "password", ""))
    assert_equal("1230de084f38ace8e3d82597f55cc6ad5d6001568e6", enzoic.send(:calc_password_hash, Enzoic::PasswordType::PliggCMS, "password", "123"))
    assert_equal("0de084f38ace8e3d82597f55cc6ad5d6001568e6", enzoic.send(:calc_password_hash, Enzoic::PasswordType::RunCMS_SMF1_1, "password", "123"))
    assert_equal("32ed87bdb5fdc5e9cba88547376818d4", enzoic.send(:calc_password_hash, Enzoic::PasswordType::NTLM, "123456", ""))
    assert_equal("55566a759b86fbbd979b579b232f4dd214d08068", enzoic.send(:calc_password_hash, Enzoic::PasswordType::SHA1Dash, "123456", "478c8029d5efddc554bf2fe6bb2219d8c897d4a0"))
    assert_equal("0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454", enzoic.send(:calc_password_hash, Enzoic::PasswordType::SHA384, "123456", ""))
    assert_equal("a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm7, "123456", "123456"))
    assert_equal("07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm9, "0rangepeel", "6kpcxVSjagLgsNCUCr-D"))
    assert_equal("$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", enzoic.send(:calc_password_hash, Enzoic::PasswordType::SHA512Crypt, "hashcat", "$6$52450745"))
    assert_equal("bd17b9d14010a1d4f8c8077f1be1e20b9364d9979bbcf8591337e952cc6037026aa4a2025543d39169022344b4dd1d20f499395533e35705296034bbf7e7d663", enzoic.send(:calc_password_hash, Enzoic::PasswordType::CustomAlgorithm10, "chatbooks", "NqXCvAHUpAWAco3hVTG5Sg0FfmJRQPKi0LvcHwylzXHhSNuWwvYdMSSGzswi0ZdJ"))
    assert_equal("$5$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", enzoic.send(:calc_password_hash, Enzoic::PasswordType::SHA256Crypt, "hashcat", "$5$rounds=5000$GX7BopJZJxPc/KEK"))
    assert_equal("$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824", enzoic.send(:calc_password_hash, Enzoic::PasswordType::AuthMeSHA256, "hashcat", "7218532375810603"))
  end

  private

  def get_enzoic
    return Enzoic::Enzoic.new(apiKey: get_api_key, secret: get_api_secret)
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
