module Enzoic
  class ArgonHashFail < StandardError; end
  ERRORS = %w(
    ARGON2_OK
    ARGON2_OUTPUT_PTR_NULL
    ARGON2_OUTPUT_TOO_SHORT
    ARGON2_OUTPUT_TOO_LONG
    ARGON2_PWD_TOO_SHORT
    ARGON2_PWD_TOO_LONG
    ARGON2_SALT_TOO_SHORT
    ARGON2_SALT_TOO_LONG
    ARGON2_AD_TOO_SHORT
    ARGON2_AD_TOO_LONG
    ARGON2_SECRET_TOO_SHORT
    ARGON2_SECRET_TOO_LONG
    ARGON2_TIME_TOO_SMALL
    ARGON2_TIME_TOO_LARGE
    ARGON2_MEMORY_TOO_LITTLE
    ARGON2_MEMORY_TOO_MUCH
    ARGON2_LANES_TOO_FEW
    ARGON2_LANES_TOO_MANY
    ARGON2_PWD_PTR_MISMATCH
    ARGON2_SALT_PTR_MISMATCH
    ARGON2_SECRET_PTR_MISMATCH
    ARGON2_AD_PTR_MISMATCH
    ARGON2_MEMORY_ALLOCATION_ERROR
    ARGON2_FREE_MEMORY_CBK_NULL
    ARGON2_ALLOCATE_MEMORY_CBK_NULL
    ARGON2_INCORRECT_PARAMETER
    ARGON2_INCORRECT_TYPE
    ARGON2_OUT_PTR_MISMATCH
    ARGON2_THREADS_TOO_FEW
    ARGON2_THREADS_TOO_MANY
    ARGON2_MISSING_ARGS
    ARGON2_ENCODING_FAIL
    ARGON2_DECODING_FAIL
    ARGON2_THREAD_FAIL
    ).freeze
end
