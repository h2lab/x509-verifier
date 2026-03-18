project('x509-verif', 'c',
  version : '1.0.0',
  default_options : [
    'warning_level=3',
    'werror=true',
    'optimization=3',
    'buildtype=release',
    'b_pie=true'
  ],
  license : 'LICENSE',
  subproject_dir : 'subprojects')

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
cc = meson.get_compiler('c')
compiler_id = cc.get_id()

# Base compilation flags
c_std_flag = ['-std=c99']
pedantic_flags = ['-pedantic', '-fno-builtin']
fortify_flags = ['-D_FORTIFY_SOURCE=2']
stack_prot_flag = ['-fstack-protector-strong']

# Compilation flags - adapted by compiler type
if compiler_id == 'clang'
  warning_flags = [
    '-Weverything',
    '-Werror',
    '-Wno-reserved-id-macro',
    '-Wno-unreachable-code-break',
    '-Wno-covered-switch-default',
    '-Wno-padded'
  ]
else
  # GCC or default
  warning_flags = [
    '-W',
    '-Werror',
    '-Wextra',
    '-Wall',
    '-Wunreachable-code'
  ]
endif

# Debug flags
debug_flags = ['-DDEBUG', '-g']

# Hardening flags
pic_flag = ['-fPIC']
# PIE is now handled via b_pie=true option
pie_ldflags = ['-Wl,-z,relro,-z,now']

# Library compilation flags (with PIC and freestaniding)
lib_cflags = warning_flags + c_std_flag + pedantic_flags + fortify_flags + stack_prot_flag + pic_flag + ['-ffreestanding']

# Binary compilation flags
bin_cflags = warning_flags + c_std_flag + pedantic_flags + fortify_flags + stack_prot_flag

# Binary linking flags (without -pie and -fpie, handled by Meson)
bin_ldflags = pie_ldflags

# Debug build configuration
if get_option('buildtype') == 'debug'
  lib_cflags += debug_flags
  bin_cflags += debug_flags
  bin_ldflags += debug_flags
endif

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

executable('x509-verif',
  src_files,
  c_args : bin_cflags,
  link_args : bin_ldflags,
  dependencies : [libsign_dep, libx509_dep],
  install : true,
  install_dir : 'bin',
  # Note: libecc generates some internal consistency check symbols that may not be resolved in all builds
  # Disable strict symbol checking for linking
  override_options: ['b_lundef=false'])
