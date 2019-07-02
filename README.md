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
if enzoic.check_password("password-to-test")
    puts("Password is compromised")
else
    puts("Password is not compromised")
end

# Check whether a specific set of credentials are compromised
if enzoic.check_credentials("test@enzoic.com", "password-to-test")
    puts("Credentials are compromised")
else
    puts("Credentials are not compromised")
end

# get all exposures for a given user
exposures = enzoic.get_exposures_for_user("test@enzoic.com")
puts(exposures.count.to_s + " exposures found for test@enzoic.com")

# now get the full details for the first exposure found
details = enzoic.get_exposure_details(exposures.exposures[0])
puts("First exposure for test@enzoic.com was " + details.title)
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
