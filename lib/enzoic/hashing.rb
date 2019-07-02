require 'enzoic/argon2_wrapper_ffi'
require 'digest'
require 'bcrypt'
require 'unix_crypt'
require 'zlib'
require 'digest/whirlpool'
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
      count = 2**itoa64.index(salt[3])
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
      return UnixCrypt::MD5.build(to_hash, salt.start_with?("$1$") ? salt[3..salt.length] : salt);
    end

    def self.custom_algorithm4(to_hash, salt)
      return self.bcrypt(self.md5(to_hash), salt)
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
