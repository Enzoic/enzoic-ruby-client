require 'argon2_import/argon2_import'

module PasswordPing
  class Argon2Wrapper
    def self.hash_argon2i_encode(password, salt, t_cost, m_cost, lanes, hash_length)
      result = "\0" * (96 + salt.length);
      ret = (Argon2::Argon2.new()).argon2_encoded(t_cost, 1 << m_cost, lanes, hash_length,
        password, salt, result, 1, 19);
      raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
      result.delete "\0"
    end

    def self.hash_argon2d_encode(password, salt, t_cost, m_cost, lanes, hash_length)
      result = "\0" * (96 + salt.length);
      ret = (Argon2::Argon2.new()).argon2_encoded(t_cost, 1 << m_cost, lanes, hash_length,
        password, salt, result, 0, 19);
      raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
      result.delete "\0"
    end

    def self.hash_argon2i(password, salt, t_cost, m_cost, lanes, hash_length)
      result = "\0" * hash_length;
      ret = (Argon2::Argon2.new()).argon2_raw(t_cost, 1 << m_cost, lanes, hash_length,
        password, salt, result, 1, 19);
      raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
      result.unpack('H*').join
    end

    def self.hash_argon2d(password, salt, t_cost, m_cost, lanes, hash_length)
      result = "\0" * hash_length;
      ret = (Argon2::Argon2.new()).argon2_raw(t_cost, 1 << m_cost, lanes, hash_length,
        password, salt, result, 0, 19);
      raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
      result.unpack('H*').join
    end
  end
end
