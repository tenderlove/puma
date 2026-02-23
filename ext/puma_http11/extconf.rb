require 'mkmf'

dir_config("puma_http11")

if $mingw
  append_cflags  '-fstack-protector-strong -D_FORTIFY_SOURCE=2'
  append_ldflags '-fstack-protector-strong -l:libssp.a'
  have_library 'ssp'
end

if ENV["PUMA_MAKE_WARNINGS_INTO_ERRORS"]
  # Make all warnings into errors
  # Except `implicit-fallthrough` since most failures comes from ragel state machine generated code
  append_cflags(config_string('WERRORFLAG') || '-Werror')
  append_cflags '-Wno-implicit-fallthrough'
end

create_makefile("puma/puma_http11")
