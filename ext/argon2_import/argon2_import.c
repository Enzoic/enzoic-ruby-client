/************************************************

  argon2.c - provides argon2 class

  Copyright (C) 2017 PasswordPing Ltd

************************************************/

#include "argon2.h"
#include "ruby.h"

static VALUE rb_mArgon2;
static VALUE rb_cArgon2;

static VALUE
tryit(VALUE inttest) {
  return INT2FIX(FIX2INT(inttest));
  //return INT2NUM(1);
}

static VALUE
argon2_raw(VALUE self, VALUE t_cost, VALUE m_cost, VALUE parallelism, VALUE hashlen, VALUE pwd, VALUE salt,
  VALUE hash, VALUE argon2type, VALUE version)
{

    Check_Type(pwd, T_STRING);
    Check_Type(salt, T_STRING);
    Check_Type(hash, T_STRING);
    FIXNUM_P(t_cost); FIXNUM_P(m_cost); FIXNUM_P(parallelism); FIXNUM_P(argon2type);
    FIXNUM_P(version); FIXNUM_P(hashlen);

    int result = argon2_hash(FIX2INT(t_cost), FIX2INT(m_cost), FIX2INT(parallelism),
      RSTRING(pwd)->ptr, RSTRING(pwd)->len,
      RSTRING(salt)->ptr, RSTRING(salt)->len, RSTRING(hash)->ptr, FIX2INT(hashlen), NULL,
      0, FIX2INT(argon2type), FIX2INT(version));

    return INT2NUM(result);
}

static VALUE
argon2_encoded(VALUE self, VALUE t_cost, VALUE m_cost, VALUE parallelism, VALUE hashlen, VALUE pwd, VALUE salt,
  VALUE encoded, VALUE argon2type, VALUE version)
{

    Check_Type(pwd, T_STRING);
    Check_Type(salt, T_STRING);
    Check_Type(encoded, T_STRING);
    FIXNUM_P(t_cost); FIXNUM_P(m_cost); FIXNUM_P(parallelism); FIXNUM_P(argon2type);
    FIXNUM_P(version); FIXNUM_P(hashlen);

  // int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
  //                 const uint32_t parallelism, const void *pwd,
  //                 const size_t pwdlen, const void *salt, const size_t saltlen,
  //                 void *hash, const size_t hashlen, char *encoded,
  //                 const size_t encodedlen, argon2_type type,
  //                 const uint32_t version)
  int result = argon2_hash(FIX2INT(t_cost), FIX2INT(m_cost), FIX2INT(parallelism),
    RSTRING(pwd)->ptr, RSTRING(pwd)->len,
    RSTRING(salt)->ptr, RSTRING(salt)->len, NULL, FIX2INT(hashlen), RSTRING(encoded)->ptr,
    RSTRING(encoded)->len, FIX2INT(argon2type), FIX2INT(version));

  return INT2NUM(result);
}

void
Init_argon2_import()
{
  rb_mArgon2 = rb_define_module("Argon2");
  rb_cArgon2 = rb_define_class_under(rb_mArgon2, "Argon2", rb_cObject);

  rb_define_method(rb_cArgon2, "tryit", tryit, 1);
  rb_define_method(rb_cArgon2, "argon2_encoded", argon2_encoded, 9);
  rb_define_method(rb_cArgon2, "argon2_raw", argon2_raw, 9);
}
