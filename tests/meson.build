test_sign = executable('test-sign',
  [
    'test.c',
    '../src/rand.c',
    '../src/libecc-compat.c',
  ],
  c_args : bin_cflags,
  dependencies : [libsign_dep],
  install : false,
)

 test_streebog = executable('test-streebog',
  [
    'test-streebog.c',
    '../src/rand.c',
    '../src/libecc-compat.c',
  ],
  c_args : bin_cflags,
  dependencies : [libsign_dep],
  install : false,
)

# Define tests that can be run with 'meson test'
# no test family used for now, but it can be useful to separate them later on
test('test-sign', test_sign)
test('test-streebog', test_streebog)
