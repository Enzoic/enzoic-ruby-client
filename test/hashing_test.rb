require 'test/unit'
require_relative "../lib/passwordping/hashing"

class HashingTest < Test::Unit::TestCase
  def test_md5
    assert_equal("e10adc3949ba59abbe56e057f20f883e", PasswordPing::Hashing.md5("123456"))
  end

  def test_sha1
    assert_equal("7c4a8d09ca3762af61e59520943dc26494f8941b", PasswordPing::Hashing.sha1("123456"))
  end

  def test_sha256
    assert_equal("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", PasswordPing::Hashing.sha256("123456"))
  end

  def test_sha512
    assert_equal("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", PasswordPing::Hashing.sha512("test"))
  end

  def test_whirlpool
    assert_equal("fd9d94340dbd72c11b37ebb0d2a19b4d05e00fd78e4e2ce8923b9ea3a54e900df181cfb112a8a73228d1f3551680e2ad9701a4fcfb248fa7fa77b95180628bb2", PasswordPing::Hashing.whirlpool("123456"))
  end

  def test_crc32
    assert_equal("972d361", PasswordPing::Hashing.crc32("123456"))
  end

  def test_mybb
    assert_equal("2e705e174e9df3e2c8aaa30297aa6d74", PasswordPing::Hashing.mybb("123456", ";;!_X"))
  end

  def test_vbulletin
    assert_equal("57ce303cdf1ad28944d43454cea38d7a", PasswordPing::Hashing.vbulletin("123456789", "]G@"))
  end

  def test_bcrypt
    assert_equal("$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", PasswordPing::Hashing.bcrypt("12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"))
  end

  def test_phpbb3
    assert_equal("$H$993WP3hbzy0N22X06wxrCc3800D2p41", PasswordPing::Hashing.phpbb3("123456789", "$H$993WP3hbz"))
  end

  def test_custom_algorithm1
    assert_equal("cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206",
      PasswordPing::Hashing.custom_algorithm1("123456", "00new00"))
  end

  def test_custom_algorithm2
    assert_equal("579d9ec9d0c3d687aaa91289ac2854e4", PasswordPing::Hashing.custom_algorithm2("123456", "123"))
  end

  def test_md5crypt
    assert_equal("$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.", PasswordPing::Hashing.md5crypt("123456", "$1$4d3c09ea"))
  end

  def test_argon2
    assert_equal("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", PasswordPing::Hashing.argon2("123456", "saltysalt"))
  end
end
