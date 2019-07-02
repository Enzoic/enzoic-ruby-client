require 'ffi'
require 'ffi-compiler/loader'

module Enzoic

  # Import of argon2 wrapper library
  module Ext
    extend FFI::Library
    ffi_lib FFI::Compiler::Loader.find('argon2-wrapper')

    # int argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
    #   const uint32_t parallelism, const void *pwd,
    #   const size_t pwdlen, const void *salt,
    #   const size_t saltlen, void *hash, const size_t hashlen);

    attach_function :argon2i_hash_raw, [
      :uint, :uint, :uint, :pointer,
      :size_t, :pointer, :size_t, :pointer, :size_t], :int, :blocking => true

    attach_function :argon2i_hash_encoded, [
      :uint, :uint, :uint, :pointer,
      :size_t, :pointer, :size_t, :size_t, :pointer, :size_t], :int, :blocking => true

    # int argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
    #   const uint32_t parallelism, const void *pwd,
    #   const size_t pwdlen, const void *salt,
    #   const size_t saltlen, void *hash, const size_t hashlen);

    attach_function :argon2d_hash_raw, [
      :uint, :uint, :uint, :pointer,
      :size_t, :pointer, :size_t, :pointer, :size_t], :int, :blocking => true

    attach_function :argon2d_hash_encoded, [
      :uint, :uint, :uint, :pointer,
      :size_t, :pointer, :size_t, :size_t, :pointer, :size_t], :int, :blocking => true
  end

  # The engine class shields users from the FFI interface.
  # It is generally not advised to directly use this class.
  class Argon2Wrapper
    def self.hash_argon2i(password, salt, t_cost, m_cost, lanes, hash_length)
      result = ''
      FFI::MemoryPointer.new(:char, hash_length) do |buffer|
        ret = Ext.argon2i_hash_raw(t_cost, 1 << m_cost, lanes, password,
           password.length, salt, salt.length,
            buffer, hash_length)
        raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
        result = buffer.read_string(hash_length)
      end
      result.unpack('H*').join
    end

    def self.hash_argon2i_encode(password, salt, t_cost, m_cost, lanes, hash_length)
      result = ''
      FFI::MemoryPointer.new(:char, 96 + salt.length) do |buffer|
        ret = Ext.argon2i_hash_encoded(t_cost, 1 << m_cost, lanes, password,
           password.length, salt, salt.length,
            hash_length, buffer, 96 + salt.length)
        raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
        result = buffer.read_string(96 + salt.length)
      end
      result.delete "\0"
    end

    def self.hash_argon2d(password, salt, t_cost, m_cost, lanes, hash_length)
      result = ''
      FFI::MemoryPointer.new(:char, hash_length) do |buffer|
        ret = Ext.argon2d_hash_raw(t_cost, 1 << m_cost, lanes, password,
           password.length, salt, salt.length,
            buffer, hash_length)
        raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
        result = buffer.read_string(hash_length)
      end
      result.unpack('H*').join
    end

    def self.hash_argon2d_encode(password, salt, t_cost, m_cost, lanes, hash_length)
      result = ''
      FFI::MemoryPointer.new(:char, 96 + salt.length) do |buffer|
        ret = Ext.argon2d_hash_encoded(t_cost, 1 << m_cost, lanes, password,
           password.length, salt, salt.length,
            hash_length, buffer, 96 + salt.length)
        raise ArgonHashFail, ERRORS[ret.abs] unless ret.zero?
        result = buffer.read_string(96 + salt.length)
      end
      result.delete "\0"
    end
  end
end
