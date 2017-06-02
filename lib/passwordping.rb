require 'passwordping/errors'
require 'passwordping/constants'
require 'passwordping/password_type'
require 'passwordping/hashing'
require 'cgi'
require 'base64'
require 'rest-client'
require 'json'
require 'ostruct'

module PasswordPing
  # This is the main entry point for accessing PasswordPing.
  #
  # Create this class with your API Key and Secret and then call the desired methods on the class
  # to access the PasswordPing API.
  class PasswordPing
    def initialize(options = {})
      @apiKey = options[:apiKey] || '';
      raise PasswordPingFail, "No API key provided" if @apiKey == ''
      @secret = options[:secret] || '';
      raise PasswordPingFail, "No Secret provided" if @secret == ''
      @baseURL = options[:baseURL] || "https://api.passwordping.com/v1"
      @authString = calc_auth_string(@apiKey, @secret)
    end

    def check_credentials(username, password)
      raise PasswordPingFail, "API key/Secret not set" if !@authString || @authString == ''

      response = make_rest_call(@baseURL + Constants::ACCOUNTS_API_PATH + "?username=" + CGI.escape(username), "GET", nil)

      if (response == "404")
        return false
      end

      account_response = JSON.parse(response)
      hashes_required = account_response["passwordHashesRequired"]

      bcrypt_count = 0
      query_string = ""

      for i in 0..hashes_required.length - 1 do
        hash_spec = hashes_required[i]

        # bcrypt gets far too expensive for good response time if there are many of them to calculate.
        # some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
        # kills performance, so short circuit out after at most 2 BCrypt hashes
        if (hash_spec["hashType"] != PasswordType::BCrypt || bcrypt_count <= 2)
          if (hash_spec["hashType"] == PasswordType::BCrypt)
            bcrypt_count = bcrypt_count + 1
          end

          if (hash_spec["hashType"] != nil)
            credential_hash = calc_credential_hash(username, password, account_response["salt"], hash_spec);

            if (credential_hash != nil)
              if (query_string.length == 0)
                query_string = query_string + "?hashes=" + CGI.escape(credential_hash);
              else
                query_string = query_string + "&hashes=" + CGI.escape(credential_hash);
              end
            end
          end
        end
      end

      if (query_string.length > 0)
        creds_response = make_rest_call(
                @baseURL + Constants::CREDENTIALS_API_PATH + query_string, "GET", nil)
        return creds_response != "404"
      end

      return false
    end

    def check_password(password)
      response = make_rest_call(
              @baseURL + Constants::PASSWORDS_API_PATH +
                  "?md5=" + Hashing.md5(password) +
                  "&sha1=" + Hashing.sha1(password) +
                  "&sha256=" + Hashing.sha256(password),
              "GET", nil)

      return response != "404"
    end

    def get_exposures_for_user(username)
      response = make_rest_call(@baseURL + Constants::EXPOSURES_API_PATH + "?username=" + CGI.escape(username),
        "GET", nil)

      if (response == "404")
        # don't have this email in the DB - return empty response
        return JSON.parse('{ "count": 0, "exposures": [] }', object_class: OpenStruct)
      else
        # deserialize response
        return JSON.parse(response, object_class: OpenStruct)
      end
    end

    def get_exposure_details(exposure_id)
      response = make_rest_call(@baseURL + Constants::EXPOSURES_API_PATH + "?id=" + CGI.escape(exposure_id),
        "GET", nil)

      if (response != "404")
        # deserialize response
        return JSON.parse(response, object_class: OpenStruct)
      else
        return nil
      end
    end

    private
      def make_rest_call(rest_url, method, body)
        begin
          response = RestClient::Request.execute(method: method, url: rest_url,
            headers: { content_type: :json, accept: :json, authorization: @authString })
          return response.body
        rescue RestClient::NotFound
          return "404"
        end
      end

      def calc_credential_hash(username, password, salt, hash_spec)
        password_hash = calc_password_hash(hash_spec["hashType"], password, hash_spec["salt"])

        if (password_hash != nil)
          argon2_hash = Hashing.argon2(username + "$" + password_hash, salt)

          just_hash = argon2_hash[argon2_hash.rindex('$') + 1 .. argon2_hash.length]
          return Base64.decode64(just_hash).unpack('H*')[0]
        else
          return nil
        end
      end

      def calc_password_hash(password_type, password, salt)
        case password_type
        when PasswordType::MD5
          return Hashing.md5(password)
        when PasswordType::SHA1
          return Hashing.sha1(password)
        when PasswordType::SHA256
          return Hashing.sha256(password)
        when PasswordType::IPBoard_MyBB
          if (salt != nil && salt.length > 0)
            return Hashing.mybb(password, salt)
          end
        when PasswordType::VBulletinPre3_8_5
          if (salt != nil && salt.length > 0)
            return Hashing.vbulletin(password, salt)
          end
        when PasswordType::VBulletinPost3_8_5
          if (salt != nil && salt.length > 0)
            return Hashing.vbulletin(password, salt)
          end
        when PasswordType::BCrypt
          if (salt != nil && salt.length > 0)
            return Hashing.bcrypt(password, salt)
          end
        when PasswordType::CRC32
          return Hashing.crc32(password)
        when PasswordType::PHPBB3
          if (salt != nil && salt.length > 0)
            return Hashing.phpbb3(password, salt)
          end
        when PasswordType::CustomAlgorithm1
          if (salt != nil && salt.length > 0)
            return Hashing.custom_algorithm1(password, salt)
          end
        when PasswordType::CustomAlgorithm2
          if (salt != nil && salt.length > 0)
            return Hashing.custom_algorithm2(password, salt)
          end
        when PasswordType::MD5Crypt
          if (salt != nil && salt.length > 0)
            return Hashing.md5crypt(password, salt)
          end
        end

        return nil
      end

      def calc_auth_string(apiKey, secret)
        return "basic " + Base64.strict_encode64(apiKey + ":" + secret);
      end
  end
end
