project('x509-verif', 'c',
  version : '1.0.0',

  default_options : [
    'c_std=c11',
    'warning_level=3',
    'optimization=3',
    'b_sanitize=address',
    'buildtype=release',
  ],
  license : 'LICENSE',
)

# Include subprojects for libraries
libecc_proj = subproject('libecc')
x509_parser_proj = subproject('x509-parser', default_options: ['default_library=static'])

# Get the library dependencies from subprojects
libsign_dep = libecc_proj.get_variable('libsign_dep')
# Use the static library directly from x509-parser
x509_parser_static_lib = x509_parser_proj.get_variable('x509_parser_static')
libx509_dep = x509_parser_proj.get_variable('libx509_dep')
# Override to use static library
libx509_dep = declare_dependency(
  include_directories: x509_parser_proj.get_variable('libx509_inc'),
  link_with: x509_parser_static_lib
)

# Compiler detection and configuration
compiler = meson.get_compiler('c')
compiler_id = compiler.get_id()

# Base compilation flags
# most of hardening flags, by now, are controlled through meson options

pedantic_flags = ['-pedantic', '-fno-builtin', '-ffreestanding']
fortify_flags = ['-D_FORTIFY_SOURCE=2']

# Library compilation flags (with PIC and freestaniding)
lib_cflags = pedantic_flags + fortify_flags

# Binary compilation flags
bin_cflags = pedantic_flags + fortify_flags

# Create the main executable
src_files = [
  'src/main.c',
  'src/x509-verif.c',
  'src/cert-extract.c',
  'src/sig-verif.c',
  'src/rand.c',
  'src/x509-parser-compat.c',
  'src/libecc-compat.c'
]

x509_verif = executable('x509-verif',
  src_files,
  c_args : bin_cflags,
  dependencies : [libsign_dep, libx509_dep],
  install : true,
  install_dir : 'bin',
)

if get_option('with_tests')
  subdir('tests')
endif
