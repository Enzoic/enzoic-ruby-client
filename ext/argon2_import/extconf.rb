require 'mkmf'

  # $srcs = ["argon2_import.c", "$(srcdir)/../phc-winner-argon2/src/argon2.c", "$(srcdir)/../phc-winner-argon2/src/core.c",
  #   "$(srcdir)/../phc-winner-argon2/src/blake2/blake2b.c", "$(srcdir)/../phc-winner-argon2/src/thread.c",
  #   "$(srcdir)/../phc-winner-argon2/src/encoding.c", "$(srcdir)/../phc-winner-argon2/src/opt.c"]
# $objs = ["argon2_import.o", "$(srcdir)/../phc-winner-argon2/src/argon2.o", "$(srcdir)/../phc-winner-argon2/src/core.o",
#   "$(srcdir)/../phc-winner-argon2/src/blake2/blake2b.o", "$(srcdir)/../phc-winner-argon2/src/thread.o",
#   "$(srcdir)/../phc-winner-argon2/src/encoding.o", "$(srcdir)/../phc-winner-argon2/src/opt.o"]

create_makefile('argon2_import')
