require 'enzoic/argon2_wrapper_ffi'
require 'digest'
require 'bcrypt'
require 'unix_crypt'
require 'zlib'
require 'digest/whirlpool.bundle'
#require 'open_ssl'
require 'base64url'

module Enzoic
  class Hashing
    def self.md5(to_hash)
      return Digest::MD5.hexdigest to_hash
    end

    def self.md5_binary(to_hash)
      return Digest::MD5.digest(to_hash).bytes
    end

    def self.md5_binary_array(to_hash_bytes)
      return Digest::MD5.digest(to_hash_bytes.pack('c*')).bytes
    end

    def self.sha1(to_hash)
      return Digest::SHA1.hexdigest to_hash
    end

    def self.sha1_binary(to_hash)
      return Digest::SHA1.digest(to_hash).bytes
    end

    def self.sha1_binary_array(to_hash_bytes)
      return Digest::SHA1.digest(to_hash_bytes.pack('c*')).bytes
    end

    def self.sha256(to_hash)
      return Digest::SHA256.hexdigest to_hash
    end

    def self.sha512(to_hash)
      return Digest::SHA512.hexdigest to_hash
    end

    def self.sha512_binary(to_hash)
      return Digest::SHA512.digest to_hash
    end

    def self.sha512_binary_array(to_hash)
      return Digest::SHA512.digest(to_hash).bytes
    end

    def self.whirlpool(to_hash)
      return Digest::Whirlpool.hexdigest(to_hash)
    end

    def self.whirlpool_binary(to_hash)
      return Digest::Whirlpool.digest(to_hash)
    end

    def self.whirlpool_binary_array(to_hash)
      return Digest::Whirlpool.digest(to_hash).bytes
    end

    def self.crc32(to_hash)
      return Zlib.crc32(to_hash, 0).to_s(16)
    end

    def self.mybb(to_hash, salt)
      return self.md5(self.md5(salt) + self.md5(to_hash))
    end

    def self.vbulletin(to_hash, salt)
      return self.md5(self.md5(to_hash) + salt)
    end

    def self.bcrypt(to_hash, salt)
      # if salt starts with $2y$, first replace with $2a$
      if salt[0..3] == "$2y$"
        y_variant = true
        checked_salt = "$2a$" + salt[4..-1]
      else
        y_variant = false
        checked_salt = salt
      end

      result = BCrypt::Engine.hash_secret(to_hash, checked_salt)

      if y_variant
        # replace with $2y$
        result = "$2y$" + result[4..-1]
      end

      return result
    end

    def self.phpbb3(to_hash, salt)
      if !salt.start_with?("$H$")
        return ""
      end

      itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
      to_hash_bytes = to_hash.bytes
      count = 2 ** itoa64.index(salt[3])
      justsalt = salt[4..12]

      hash = self.md5_binary(justsalt + to_hash)
      loop do
        hash = self.md5_binary_array(hash.push(to_hash_bytes).flatten!)
        count = count - 1;
        break if count == 0
      end

      hashout = ""
      i = 0
      count = 16
      value = 0

      loop do
        value = hash[i] + (hash[i] < 0 ? 256 : 0)
        i = i + 1
        hashout = hashout + itoa64[value & 63]
        if i < count
          value = value | (hash[i] + (hash[i] < 0 ? 256 : 0)) << 8;
        end

        hashout = hashout + itoa64[(value >> 6) & 63]
        i = i + 1
        if (i >= count)
          break
        end

        if (i < count)
          value = value | (hash[i] + (hash[i] < 0 ? 256 : 0)) << 16
        end

        hashout = hashout + itoa64[(value >> 12) & 63]

        i = i + 1
        if (i >= count)
          break
        end

        hashout = hashout + itoa64[(value >> 18) & 63]

        break if i == count
      end

      return salt + hashout
    end

    def self.custom_algorithm1(to_hash, salt)
      return self.bytes_to_hex(self.xor(self.sha512_binary_array(to_hash + salt), self.whirlpool_binary_array(salt + to_hash)))
    end

    def self.custom_algorithm2(to_hash, salt)
      return self.md5(to_hash + salt)
    end

    def self.md5crypt(to_hash, salt)
      return UnixCrypt::MD5.build(to_hash, salt.start_with?("$1$") ? salt[3..salt.length] : salt)
    end

    def self.custom_algorithm4(to_hash, salt)
      return self.bcrypt(self.md5(to_hash), salt)
    end

    def self.custom_algorithm5(to_hash, salt)
      return self.sha256(self.md5(to_hash + salt))
    end

    def self.osCommerce_AEF(to_hash, salt)
      return self.md5(salt + to_hash)
    end

    def self.desCrypt(to_hash, salt)
      return UnixCrypt::DES.build(to_hash, salt)
    end

    def self.convertToUnsigned(val)
      return [val].pack('L').unpack('L').first
    end

    def self.mySQLPre4_1(to_hash)
      nr = 1345345333
      add = 7
      nr2 = 0x12345671

      for i in 0..to_hash.length - 1 do
        c = to_hash[i]

        if c == " " || c == "\t"
          next
        end

        tmp = c.ord
        nr = nr ^ ((((nr & 63) + add) * tmp) + (self.convertToUnsigned(nr << 8)))
        nr2 += (self.convertToUnsigned(nr2 << 8)) ^ nr
        add += tmp
      end

      result1 = nr & ((self.convertToUnsigned(1 << 31)) - 1)
      result2 = nr2 & ((self.convertToUnsigned(1 << 31)) - 1)

      return result1.to_s(16) + result2.to_s(16)
    end

    def self.mySQLPost4_1(to_hash)
      return "*" + self.bytes_to_hex(self.sha1_binary_array(self.sha1_binary(to_hash)));
    end

    def self.punBB(to_hash, salt)
      return self.sha1(salt + self.sha1(to_hash))
    end

    def self.custom_algorithm6(to_hash, salt)
      return self.sha1(to_hash + salt)
    end

    def self.partial_md5_20(to_hash)
      return self.md5(to_hash)[0..19]
    end

    def self.partial_md5_29(to_hash)
      return self.md5(to_hash)[0..28]
    end

    def self.ave_datalife_diferior(to_hash)
      return self.md5(self.md5(to_hash))
    end

    def self.django_md5(to_hash, salt)
      return "md5$" + salt + "$" + self.md5(salt + to_hash)
    end

    def self.django_sha1(to_hash, salt)
      return "sha1$" + salt + "$" + self.sha1(salt + to_hash)
    end

    def self.pligg_cms(to_hash, salt)
      return salt + self.sha1(salt + to_hash)
    end

    def self.runcms_smf1_1(to_hash, salt)
      return self.sha1(salt + to_hash)
    end

    def self.ntlm(to_hash)
      pwd = to_hash.dup
      pwd = pwd.dup.force_encoding('UTF-8').encode(Encoding::UTF_16LE, Encoding::UTF_8).force_encoding('UTF-8')
      OpenSSL::Digest::MD4.hexdigest pwd
    end

    def self.sha1dash(to_hash, salt)
      return self.sha1("--" + salt + "--" + to_hash + "--")
    end

    def self.sha384(to_hash)
      return Digest::SHA384.hexdigest to_hash
    end

    def self.custom_algorithm7(to_hash, salt)
      derived_salt = self.sha1(salt)
      return OpenSSL::HMAC.hexdigest("SHA256",
                                     "d2e1a4c569e7018cc142e9cce755a964bd9b193d2d31f02d80bb589c959afd7e",
                                     derived_salt + to_hash)
    end

    def self.custom_algorithm9(to_hash, salt)
      result = self.sha512(to_hash + salt)
      for i in 0..10 do
        result = self.sha512(result)
      end
      return result
    end

    def self.sha256crypt(to_hash, salt)
      return self.sha_crypt("5", UnixCrypt::SHA256, to_hash, salt)
    end

    def self.sha512crypt(to_hash, salt)
      return self.sha_crypt("6", UnixCrypt::SHA512, to_hash, salt)
    end

    def self.sha_crypt(crypt_version, crypter, to_hash, salt)
      # special handling if the salt contains an embedded rounds specifier
      if salt.start_with?("$" + crypt_version + "$") && salt.include?("$rounds=")
        # extract rounds
        rounds_starting_idx = salt.index("$rounds=") + 8
        rounds = salt[rounds_starting_idx..salt.length]
        salt_portion = rounds[rounds.index("$") + 1..rounds.length]

        begin
          rounds = Integer(rounds[0..rounds.index("$") - 1])
        rescue ArgumentError
          rounds = 5000
        end

        result = crypter.build(to_hash, salt_portion, rounds)

        # if the default rounds of 5000 was used, add this back in to the resultant hash as this library, unlike most,
        # will strip it out.
        if rounds == 5000
          result = result[0..2] + "rounds=5000$" + result[3..result.length]
        end

        return result
      end
      return crypter.build(to_hash, salt.start_with?("$" + crypt_version + "$") ? salt[3..salt.length] : salt)
    end

    def self.custom_algorithm10(to_hash, salt)
      return self.sha512(to_hash + ":" + salt)
    end

    def self.hmac_sha1_salt_as_hash(to_hash, salt)
      return OpenSSL::HMAC.hexdigest("sha1", salt, to_hash)
    end

    def self.authMeSHA256(to_hash, salt)
      return "$SHA$" + salt + "$" + self.sha256(self.sha256(to_hash) + salt);
    end

    def self.argon2_raw(to_hash, salt)
      time_cost = 3
      mem_cost = 10
      threads = 2
      hash_length = 20
      just_salt = salt

      #$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
      if (salt[0..6] == "$argon2")
        # looks like we specified algo info for argon2 in the salt
        salt_values = salt.split("$")
        just_salt = Base64URL.decode(salt_values[4])
        cost_params = salt_values[3].split(",")

        for param in cost_params
          begin
            param_parts = param.split("=")
            if (param_parts[0] == "t")
              time_cost = Integer(param_parts[1])
            elsif (param_parts[0] == "m")
              mem_cost = Math.log2(Integer(param_parts[1])).round
            elsif (param_parts[0] == "p")
              threads = Integer(param_parts[1])
            elsif (param_parts[0] == "l")
              hash_length = Integer(param_parts[1])
            end
          rescue ArgumentError
            # ignore invalid params and just use default
          end
        end

        if (salt_values[1] == "argon2i")
          return Argon2Wrapper.hash_argon2i(to_hash, just_salt, time_cost, mem_cost, threads, hash_length)
        else
          return Argon2Wrapper.hash_argon2d(to_hash, just_salt, time_cost, mem_cost, threads, hash_length)
        end
      else
        return Argon2Wrapper.hash_argon2d(to_hash, just_salt, time_cost, mem_cost, threads, hash_length)
      end
    end

    def self.argon2(to_hash, salt)
      time_cost = 3
      mem_cost = 10
      threads = 2
      hash_length = 20
      just_salt = salt

      #$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
      if (salt[0..6] == "$argon2")
        # looks like we specified algo info for argon2 in the salt
        salt_values = salt.split("$")
        just_salt = Base64URL.decode(salt_values[4])
        cost_params = salt_values[3].split(",")

        for param in cost_params
          begin
            param_parts = param.split("=")
            if (param_parts[0] == "t")
              time_cost = Integer(param_parts[1])
            elsif (param_parts[0] == "m")
              mem_cost = Math.log2(Integer(param_parts[1])).round
            elsif (param_parts[0] == "p")
              threads = Integer(param_parts[1])
            elsif (param_parts[0] == "l")
              hash_length = Integer(param_parts[1])
            end
          rescue ArgumentError
            # ignore invalid params and just use default
          end
        end

        if (salt_values[1] == "argon2i")
          return Argon2Wrapper.hash_argon2i_encode(to_hash, just_salt, time_cost, mem_cost, threads, hash_length)
        else
          return Argon2Wrapper.hash_argon2d_encode(to_hash, just_salt, time_cost, mem_cost, threads, hash_length)
        end
      else
        return Argon2Wrapper.hash_argon2d_encode(to_hash, just_salt, time_cost, mem_cost, threads, hash_length)
      end
    end

    def self.xor(byte_array1, byte_array2)
      result = Array.new(byte_array1.length);

      for i in 0..byte_array1.length - 1 do
        result[i] = byte_array1[i] ^ byte_array2[i];
      end

      return result;
    end

    def self.bytes_to_hex(bytes)
      return bytes.pack('c*').unpack('H*')[0]
    end

    def self.hex_to_bytes(hex)
      hex.scan(/../).map { |x| x.hex }.pack('c*')
    end
  end
end
