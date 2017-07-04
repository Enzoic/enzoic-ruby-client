# PasswordPing Ruby Client Library

PLEASE NOTE: THIS IS A BRANCH OF THE PASSWORDPING RUBY LIBRARY MEANT TO SUPPORT EARLIER VERSIONS OF RUBY, FROM 1.8.7 UP.  IF YOU DO
NOT NEED LEGACY RUBY SUPPORT, USE THE MASTER BRANCH VERSION: https://github.com/passwordping/passwordping-ruby-client

## TOC

This README covers the following topics:

- [Installation](#installation)
- [Source](#source)
- [API Overview](#api-overview)
- [The PasswordPing constructor](#the-passwordping-constructor)
- [Platform Requirements](#platform-requirements)
- [RubyDocs](#rubydocs)

## Installation

The compiled library is available as a Ruby Gem:

```shell
gem install passwordping_legacy
```

### Source

You can build the project from the source in this repository.

## API Overview

Here's the API in a nutshell.

```ruby
require 'passwordping'

# Create a new PasswordPing instance - this is our primary interface for making API calls
passwordping = PasswordPing::PasswordPing.new(YOUR_API_KEY, YOUR_API_SECRET)

# Check whether a password has been compromised
if passwordping.check_password("password-to-test")
    puts("Password is compromised")
else
    puts("Password is not compromised")
end

# Check whether a specific set of credentials are compromised
if passwordping.check_credentials("test@passwordping.com", "password-to-test")
    puts("Credentials are compromised")
else
    puts("Credentials are not compromised")
end

# get all exposures for a given user
exposures = passwordping.get_exposures_for_user("test@passwordping.com")
puts(exposures.count.to_s + " exposures found for test@passwordping.com")

# now get the full details for the first exposure found
details = passwordping.get_exposure_details(exposures.exposures[0])
puts("First exposure for test@passwordping.com was " + details.title)
```

More information in reference format can be found below.

## The PasswordPing constructor

The standard constructor takes the API key and secret you were issued on PasswordPing signup.

```ruby
passwordping = PasswordPing::PasswordPing.new(YOUR_API_KEY, YOUR_API_SECRET)
```

If you were instructed to use an alternate API endpoint, you may call the overloaded constructor and pass the base URL you were provided.

```ruby
passwordping = PasswordPing::PasswordPing.new(YOUR_API_KEY, YOUR_API_SECRET, "https://api-alt.passwordping.com/v1")
```

## Platform Requirements

All platforms are fully supported.  

Ruby 1.8.7 and up are supported by this version.  If you do not require legacy Ruby support, use the version of this library in the master branch.

## RubyDocs

The RubyDocs contain more complete references for the API functions.  

They can be found here: <http://www.rubydoc.info/gems/passwordping_legacy>

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
