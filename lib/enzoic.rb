require 'enzoic/errors'
require 'enzoic/constants'
require 'enzoic/password_type'
require 'enzoic/hashing'
require 'cgi'
require 'base64'
require 'rest-client'
require 'json'
require 'ostruct'

module Enzoic
  # This is the main entry point for accessing Enzoic.
  #
  # Create this class with your API Key and Secret and then call the desired methods on the class
  # to access the Enzoic API.
  class Enzoic
    def initialize(options = {})
      @apiKey = options[:apiKey] || ''
      raise EnzoicFail, "No API key provided" if @apiKey == ''
      @secret = options[:secret] || ''
      raise EnzoicFail, "No Secret provided" if @secret == ''
      @baseURL = options[:baseURL] || "https://api.enzoic.com/v1"
      @authString = calc_auth_string(@apiKey, @secret)
    end

    def check_credentials(username, password, last_check_timestamp = Date.new(1980, 1, 1))
      raise EnzoicFail, "API key/Secret not set" if !@authString || @authString == ''

      response = make_rest_call(@baseURL + Constants::ACCOUNTS_API_PATH +
                                  "?username=" + Hashing.sha256(username.downcase),
                                "GET", nil)

      if response == "404"
        return false
      end

      account_response = JSON.parse(response)

      # if lastCheckTimestamp was provided, see if we need to go any further
      if Date.parse(account_response["lastBreachDate"]) > last_check_timestamp
        hashes_required = account_response["passwordHashesRequired"]

        bcrypt_count = 0
        query_string = ""
        credential_hashes = []

        hashes_required.each do |hash_spec|
          # bcrypt gets far too expensive for good response time if there are many of them to calculate.
          # some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
          # kills performance, so short circuit out after at most 2 BCrypt hashes
          if hash_spec["hashType"] != PasswordType::BCrypt || bcrypt_count <= 2
            if hash_spec["hashType"] == PasswordType::BCrypt
              bcrypt_count = bcrypt_count + 1
            end

            if hash_spec["hashType"] != nil
              credential_hash = calc_credential_hash(username.downcase, password, account_response["salt"], hash_spec)

              if credential_hash != nil
                credential_hashes << credential_hash

                if query_string.length == 0
                  query_string = query_string + "?partialHashes=" + CGI.escape(credential_hash[0..6])
                else
                  query_string = query_string + "&partialHashes=" + CGI.escape(credential_hash[0..6])
                end
              end
            end
          end
        end

        if query_string.length > 0
          creds_response = make_rest_call(
            @baseURL + Constants::CREDENTIALS_API_PATH + query_string, "GET", nil)

          if creds_response != "404"
            creds_result = JSON.parse(creds_response, object_class: OpenStruct)
            creds_result.candidateHashes.each do |candidateHash|
              if credential_hashes.include? candidateHash
                return true
              end
            end
          end
        end
      end

      return false
    end

    def check_password(password)
      md5 = Hashing.md5(password)
      sha1 = Hashing.sha1(password)
      sha256 = Hashing.sha256(password)

      response = make_rest_call(
        @baseURL + Constants::PASSWORDS_API_PATH, "POST",
        '{' +
          '"partialMD5":"' + md5[0..6] + '",' +
          '"partialSHA1":"' + sha1[0..6] + '",' +
          '"partialSHA256":"' + sha256[0..6] + '"' +
          '}')

      if response != "404"
        result = JSON.parse(response, object_class: OpenStruct)

        result.candidates.each do |candidate|
          if candidate.md5 == md5 || candidate.sha1 == sha1 || candidate.sha256 == sha256
            return true
          end
        end
      end

      return false
    end

    def get_exposures_for_user(username)
      response = make_rest_call(@baseURL + Constants::EXPOSURES_API_PATH + "?username=" + Hashing.sha256(username.downcase),
                                "GET", nil)

      if response == "404"
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

      if response != "404"
        # deserialize response
        return JSON.parse(response, object_class: OpenStruct)
      else
        return nil
      end
    end

    def get_passwords_for_user(username)
      response = make_rest_call(@baseURL + Constants::ACCOUNTS_API_PATH + "?username=" +
                                  Hashing.sha256(username.downcase) + "&includePasswords=1",
                                "GET", nil)

      if response == "404"
        # don't have this email in the DB - return empty response
        return JSON.parse('{ "lastBreachDate": null, "passwords": [] }', object_class: OpenStruct)
      else
        # deserialize response
        return JSON.parse(response, object_class: OpenStruct)
      end
    end

    private

    def make_rest_call(rest_url, method, body)
      begin
        response = RestClient::Request.execute(method: method, url: rest_url,
                                               payload: body,
                                               headers: { content_type: :json, accept: :json, authorization: @authString })
        return response.body
      rescue RestClient::NotFound
        return "404"
      end
    end

    def calc_credential_hash(username, password, salt, hash_spec)
      password_hash = calc_password_hash(hash_spec["hashType"], password, hash_spec["salt"])

      if password_hash != nil
        return Hashing.argon2_raw(username.downcase + "$" + password_hash, salt)
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
      when PasswordType::SHA512
        return Hashing.sha512(password)
      when PasswordType::IPBoard_MyBB
        if salt != nil && salt.length > 0
          return Hashing.mybb(password, salt)
        end
      when PasswordType::VBulletinPre3_8_5
        if salt != nil && salt.length > 0
          return Hashing.vbulletin(password, salt)
        end
      when PasswordType::VBulletinPost3_8_5
        if salt != nil && salt.length > 0
          return Hashing.vbulletin(password, salt)
        end
      when PasswordType::BCrypt
        if salt != nil && salt.length > 0
          return Hashing.bcrypt(password, salt)
        end
      when PasswordType::CRC32
        return Hashing.crc32(password)
      when PasswordType::PHPBB3
        if salt != nil && salt.length > 0
          return Hashing.phpbb3(password, salt)
        end
      when PasswordType::CustomAlgorithm1
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm1(password, salt)
        end
      when PasswordType::CustomAlgorithm2
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm2(password, salt)
        end
      when PasswordType::MD5Crypt
        if salt != nil && salt.length > 0
          return Hashing.md5crypt(password, salt)
        end
      when PasswordType::CustomAlgorithm4
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm4(password, salt)
        end
      when PasswordType::CustomAlgorithm5
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm5(password, salt)
        end
      when PasswordType::OsCommerce_AEF
        if salt != nil && salt.length > 0
          return Hashing.osCommerce_AEF(password, salt)
        end
      when PasswordType::DESCrypt
        if salt != nil && salt.length > 0
          return Hashing.desCrypt(password, salt)
        end
      when PasswordType::MySQLPre4_1
        return Hashing.mySQLPre4_1(password)
      when PasswordType::MySQLPost4_1
        return Hashing.mySQLPost4_1(password)
      when PasswordType::PunBB
        if salt != nil && salt.length > 0
          return Hashing.punBB(password, salt)
        end
      when PasswordType::CustomAlgorithm6
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm6(password, salt)
        end
      when PasswordType::PartialMD5_20
        return Hashing.partial_md5_20(password)
      when PasswordType::AVE_DataLife_Diferior
        return Hashing.ave_datalife_diferior(password)
      when PasswordType::DjangoMD5
        if salt != nil && salt.length > 0
          return Hashing.django_md5(password, salt)
        end
      when PasswordType::DjangoSHA1
        if salt != nil && salt.length > 0
          return Hashing.django_sha1(password, salt)
        end
      when PasswordType::PartialMD5_29
        return Hashing.partial_md5_29(password)
      when PasswordType::PliggCMS
        if salt != nil && salt.length > 0
          return Hashing.pligg_cms(password, salt)
        end
      when PasswordType::RunCMS_SMF1_1
        if salt != nil && salt.length > 0
          return Hashing.runcms_smf1_1(password, salt)
        end
      when PasswordType::NTLM
        return Hashing.ntlm(password)
      when PasswordType::SHA1Dash
        if salt != nil && salt.length > 0
          return Hashing.sha1dash(password, salt)
        end
      when PasswordType::SHA384
        return Hashing.sha384(password)
      when PasswordType::CustomAlgorithm7
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm7(password, salt)
        end
      when PasswordType::CustomAlgorithm9
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm9(password, salt)
        end
      when PasswordType::SHA512Crypt
        if salt != nil && salt.length > 0
          return Hashing.sha512crypt(password, salt)
        end
      when PasswordType::CustomAlgorithm10
        if salt != nil && salt.length > 0
          return Hashing.custom_algorithm10(password, salt)
        end
      when PasswordType::SHA256Crypt
        if salt != nil && salt.length > 0
          return Hashing.sha256crypt(password, salt)
        end
      when PasswordType::AuthMeSHA256
        if salt != nil && salt.length > 0
          return Hashing.authMeSHA256(password, salt)
        end
      else
        return nil
      end
    end

    def calc_auth_string(api_key, secret)
      return "basic " + Base64.strict_encode64(api_key + ":" + secret)
    end
  end
end
