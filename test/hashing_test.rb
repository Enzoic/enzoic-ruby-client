require 'test/unit'
require_relative "../lib/enzoic/hashing"

class HashingTest < Test::Unit::TestCase
  def test_md5
    assert_equal("e10adc3949ba59abbe56e057f20f883e", Enzoic::Hashing.md5("123456"))
  end

  def test_sha1
    assert_equal("7c4a8d09ca3762af61e59520943dc26494f8941b", Enzoic::Hashing.sha1("123456"))
  end

  def test_sha256
    assert_equal("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", Enzoic::Hashing.sha256("123456"))
  end

  def test_sha512
    assert_equal("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", Enzoic::Hashing.sha512("test"))
  end

  def test_whirlpool
    assert_equal("fd9d94340dbd72c11b37ebb0d2a19b4d05e00fd78e4e2ce8923b9ea3a54e900df181cfb112a8a73228d1f3551680e2ad9701a4fcfb248fa7fa77b95180628bb2", Enzoic::Hashing.whirlpool("123456"))
  end

  def test_crc32
    assert_equal("972d361", Enzoic::Hashing.crc32("123456"))
  end

  def test_mybb
    assert_equal("2e705e174e9df3e2c8aaa30297aa6d74", Enzoic::Hashing.mybb("123456", ";;!_X"))
  end

  def test_vbulletin
    assert_equal("57ce303cdf1ad28944d43454cea38d7a", Enzoic::Hashing.vbulletin("123456789", "]G@"))
  end

  def test_bcrypt
    assert_equal("$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", Enzoic::Hashing.bcrypt("12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"))
  end

  def test_phpbb3
    assert_equal("$H$993WP3hbzy0N22X06wxrCc3800D2p41", Enzoic::Hashing.phpbb3("123456789", "$H$993WP3hbz"))
  end

  def test_custom_algorithm1
    assert_equal("cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206",
      Enzoic::Hashing.custom_algorithm1("123456", "00new00"))
  end

  def test_custom_algorithm2
    assert_equal("579d9ec9d0c3d687aaa91289ac2854e4", Enzoic::Hashing.custom_algorithm2("123456", "123"))
  end

  def test_custom_algorithm4
    assert_equal("$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W", Enzoic::Hashing.custom_algorithm4("1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZO"))
  end

  def test_custom_algorithm5
    assert_equal("69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163", Enzoic::Hashing.custom_algorithm5("password", "123456"))
  end

  def test_osCommerce_AEF
    assert_equal("d2bc2f8d09990ebe87c809684fd78c66", Enzoic::Hashing.osCommerce_AEF("password", "123"))
  end

  def test_md5crypt
    assert_equal("$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.", Enzoic::Hashing.md5crypt("123456", "$1$4d3c09ea"))
  end

  def test_descrypt
    assert_equal("X.OPW8uuoq5N.", Enzoic::Hashing.desCrypt("password", "X."))
  end

  def test_mySQLPre4_1
    assert_equal("5d2e19393cc5ef67", Enzoic::Hashing.mySQLPre4_1("password"))
  end

  def test_mySQLPost4_1
    assert_equal("*94bdcebe19083ce2a1f959fd02f964c7af4cfc29", Enzoic::Hashing.mySQLPost4_1("test"))
  end

  def test_punBB
    assert_equal("0c9a0dc3dd0b067c016209fd46749c281879069e", Enzoic::Hashing.punBB("password", "123"))
  end

  def test_custom_algorithm6
    assert_equal("cbfdac6008f9cab4083784cbd1874f76618d2a97", Enzoic::Hashing.custom_algorithm6("password", "123"))
  end

  def test_partial_md5_20
    assert_equal("5f4dcc3b5aa765d61d83", Enzoic::Hashing.partial_md5_20("password"))
  end

  def test_partial_md5_29
    assert_equal("5f4dcc3b5aa765d61d8327deb882c", Enzoic::Hashing.partial_md5_29("password"))
  end

  def test_ave_datalife_diferior
    assert_equal("696d29e0940a4957748fe3fc9efd22a3", Enzoic::Hashing.ave_datalife_diferior("password"))
  end

  def test_django_md5
    assert_equal("md5$c6218$346abd81f2d88b4517446316222f4276", Enzoic::Hashing.django_md5("password", "c6218"))
  end

  def test_django_sha1
    assert_equal("sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845", Enzoic::Hashing.django_sha1("password", "c6218"))
  end

  def test_pligg_cms
    assert_equal("1230de084f38ace8e3d82597f55cc6ad5d6001568e6", Enzoic::Hashing.pligg_cms("password", "123"))
  end

  def test_runcms_smf1_1
    assert_equal("0de084f38ace8e3d82597f55cc6ad5d6001568e6", Enzoic::Hashing.runcms_smf1_1("password", "123"))
  end

  def test_ntlm
    assert_equal("32ed87bdb5fdc5e9cba88547376818d4", Enzoic::Hashing.ntlm("123456"))
  end

  def test_sha1dash
    assert_equal("55566a759b86fbbd979b579b232f4dd214d08068", Enzoic::Hashing.sha1dash("123456", "478c8029d5efddc554bf2fe6bb2219d8c897d4a0"))
  end

  def test_sha384
    assert_equal("0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454", Enzoic::Hashing.sha384("123456"))
  end

  def test_custom_algorithm7
    assert_equal("a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982",
                 Enzoic::Hashing.custom_algorithm7("123456", "123456"))
  end

  def test_custom_algorithm9
    assert_equal("07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc",
                 Enzoic::Hashing.custom_algorithm9("0rangepeel", "6kpcxVSjagLgsNCUCr-D"))
  end

  def test_sha256crypt
    assert_equal("$5$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD",
                 Enzoic::Hashing.sha256crypt("hashcat", "$5$GX7BopJZJxPc/KEK"))
    # try with rounds specifier
    assert_equal("$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD",
                 Enzoic::Hashing.sha256crypt("hashcat", "$5$rounds=5000$GX7BopJZJxPc/KEK"))
    assert_equal("$5$rounds=4000$GX7BopJZJxPc/KEK$sn.Ds3.Gebi0n6vih/PyOUqlagz5FGk1ITvNh7f1ZMC",
                 Enzoic::Hashing.sha256crypt("hashcat", "$5$rounds=4000$GX7BopJZJxPc/KEK"))
    assert_equal("$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD",
                 Enzoic::Hashing.sha256crypt("hashcat", "$5$rounds=sds$GX7BopJZJxPc/KEK"))
  end

  def test_sha512crypt
    assert_equal("$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/",
                 Enzoic::Hashing.sha512crypt("hashcat", "$6$52450745"))
    # try with rounds specifier
    assert_equal("$6$rounds=5000$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/",
                 Enzoic::Hashing.sha512crypt("hashcat", "$6$rounds=5000$52450745"))
    assert_equal("$6$rounds=4000$52450745$SpwN1flz4M8T.VckR9l.UofKPTtPvUx3ZfNSAQ.ruUsFBCvC1mz49quqhSrPjK4p25hfLcDZF/86iiA0n38Dh/",
                 Enzoic::Hashing.sha512crypt("hashcat", "$6$rounds=4000$52450745"))
  end

  def test_custom_algorithm10
    assert_equal("bd17b9d14010a1d4f8c8077f1be1e20b9364d9979bbcf8591337e952cc6037026aa4a2025543d39169022344b4dd1d20f499395533e35705296034bbf7e7d663",
                 Enzoic::Hashing.custom_algorithm10("chatbooks", "NqXCvAHUpAWAco3hVTG5Sg0FfmJRQPKi0LvcHwylzXHhSNuWwvYdMSSGzswi0ZdJ"))
  end

  def test_hmac_sha1_salt_as_hash
    assert_equal("d89c92b4400b15c39e462a8caa939ab40c3aeeea",
                 Enzoic::Hashing.hmac_sha1_salt_as_hash("hashcat", "1234"))
  end

  def test_authMeSHA256
    assert_equal("$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824",
                 Enzoic::Hashing.authMeSHA256("hashcat", "7218532375810603"))
  end

  def test_argon2
    assert_equal("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Enzoic::Hashing.argon2("123456", "saltysalt"))
    assert_equal("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Enzoic::Hashing.argon2("123456", "$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0"))
    assert_equal("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", Enzoic::Hashing.argon2("password", "$argon2i$v=19$m=65536,t=2,p=4,l=24$c29tZXNhbHQ"))

    # ensure exception handling works for invalid params
    assert_equal("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Enzoic::Hashing.argon2("123456", "$argon2d$v=19$m=10d2,t=ejw,p=2$c2FsdHlzYWx0"))
  end

  def test_argon2_raw
    assert_equal("12494620fb424966f7212faae0843baf0af09b6a", Enzoic::Hashing.argon2_raw("123456", "saltysalt"))
    assert_equal("12494620fb424966f7212faae0843baf0af09b6a", Enzoic::Hashing.argon2_raw("123456", "$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0"))
    assert_equal("45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6", Enzoic::Hashing.argon2_raw("password", "$argon2i$v=19$m=65536,t=2,p=4,l=24$c29tZXNhbHQ"))

    # ensure exception handling works for invalid params
    assert_equal("12494620fb424966f7212faae0843baf0af09b6a", Enzoic::Hashing.argon2_raw("123456", "$argon2d$v=19$m=10d2,t=ejw,p=2$c2FsdHlzYWx0"))
  end
end
