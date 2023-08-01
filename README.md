# Enzoic Ruby Client Library


## TOC

This README covers the following topics:

- [Installation](#installation)
- [Source](#source)
- [API Overview](#api-overview)
- [The Enzoic constructor](#the-enzoic-constructor)
- [Platform Requirements](#platform-requirements)
- [RubyDocs](#rubydocs)

## Installation

The compiled library is available as a Ruby Gem:

```shell
gem install enzoic
```

### Source

You can build the project from the source in this repository.

## API Overview

Here's the API in a nutshell.

```ruby
require 'enzoic'

# Create a new Enzoic instance - this is our primary interface for making API calls
enzoic = Enzoic::Enzoic.new(apiKey: YOUR_API_KEY, secret: YOUR_API_SECRET)

# Check whether a password has been compromised
# for more information, see 
# https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api
if enzoic.check_password("password-to-test")
    puts("Password is compromised")
else
    puts("Password is not compromised")
end

# Check whether a specific set of credentials are compromised
# for more information, see 
# https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/hashed-credentials-api 
if enzoic.check_credentials("test@enzoic.com", "password-to-test")
    puts("Credentials are compromised")
else
    puts("Credentials are not compromised")
end

# Check whether a specific set of credentials are compromised, using the optional 
# lastCheckData parameter.
# lastCheckDate is the timestamp for the last check you performed for this user.
# If the DateTime you provide for the last check is greater than the timestamp Enzoic has 
# for the last breach affecting this user, the check will not be performed.  
# This can be used to substantially increase performance.
if enzoic.check_credentials("test@enzoic.com", "password-to-test", DateTime.parse("2019-07-15T19:57:43.000Z"))
    puts("Credentials are compromised")
else
    puts("Credentials are not compromised")
end

# get all exposures for a given user
# for more information, see 
# https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-an-email-address
exposures = enzoic.get_exposures_for_user("test@enzoic.com")
puts(exposures.count.to_s + " exposures found for test@enzoic.com")

# now get the full details for the first exposure found
# for more information, see 
# https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/retrieve-details-for-an-exposure
details = enzoic.get_exposure_details(exposures.exposures[0])
puts("First exposure for test@enzoic.com was " + details.title)

# get all passwords for a given user - requires special approval, contact Enzoic sales
# for more information, see 
# https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
user_passwords = enzoic.get_passwords_for_user("eicar_0@enzoic.com", true)
puts("First password for eicar_0@enzoic.com was " + user_passwords.passwords[0].password)

```

More information in reference format can be found below.

## The Enzoic constructor

The standard constructor takes the API key and secret you were issued on Enzoic signup.

```ruby
enzoic = Enzoic::Enzoic.new(apiKey: YOUR_API_KEY, secret: YOUR_API_SECRET)
```

If you were instructed to use an alternate API endpoint, you may call the overloaded constructor and pass the base URL you were provided.

```ruby
enzoic = Enzoic::Enzoic.new(apiKey: YOUR_API_KEY, secret: YOUR_API_SECRET, baseURL: "https://api-alt.enzoic.com/v1")
```

## Platform Requirements

OSX and Linux platforms are fully supported.  Windows is not, since FFI support is needed for some of the cryptography libraries, which is problematic on Windows.

Ruby 2.0.0 and up are supported.

## RubyDocs

The RubyDocs contain more complete references for the API functions.  

They can be found here: <http://www.rubydoc.info/gems/enzoic>

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
