rand_source_files = files(
  '../src/rand.c',
  '../src/libecc-compat.c',
)

test_sign = executable('test-sign',
  [
    'test.c',
    rand_source_files,
  ],
  c_args : bin_cflags,
  dependencies : [libsign_dep],
  install : false,
)

test_streebog = executable('test-streebog',
  [
    'test-streebog.c',
    rand_source_files,
  ],
  c_args : bin_cflags,
  dependencies : [libsign_dep],
  install : false,
)

# basic test suite
test(
  'test-sign',
  test_sign,
  suite: 'basic',
  timeout: 30,
)

test(
  'test-streebog',
  test_streebog,
  suite: 'basic',
  timeout: 30,
)


# Artifact-based integration tests for x509-verif
#
# Uses tests/list_cert_pairs.py (run at configure time) to discover
# cert-anchor pairs from the artifacts/ directory.  Each discovered pair
# becomes one meson test that exercises the x509-verif binary.
#
# Suites produced by the helper script:
#   gost-self-signed   – self-signed certs from artifacts/all-gosts-self-signed/
#   gost-2012          – self-signed certs from artifacts/all-gost-sig2012/
#   gost-2012-cross    – anchored certs from artifacts/all-gost-sig2012/
#   gost-ca            – self-signed CA-like certs from artifacts/all-gosts/
#   gost-ca-cross      – anchored CA-like certs from artifacts/all-gosts/
#   gost-cert-self     – self-signed leaf certs from artifacts/all-gosts/
#   gost-cert-cross    – anchored leaf certs from artifacts/all-gosts/
#   gost-exotic-self   – self-signed certs from artifacts/exotic/GOST/
#   gost-exotic-cross  – anchored certs from artifacts/exotic/GOST/
#   gost-roots         – self-signed certs from artifacts/exotic/gost-root/
#   gost-roots-cross   – anchored certs from artifacts/exotic/gost-root/
#   ed25519            – self-signed certs from artifacts/exotic/ED25519/
#   ed25519-cross      – anchored certs from artifacts/exotic/ED25519/
#   ed448              – self-signed Ed448 certs
#   ed448-cross        – anchored Ed448 certs
#   sm2                – self-signed SM2 certs
#   sm2-cross          – anchored SM2 certs
#   rfc4491            – RFC 4491 GOST vectors under artifacts/
#   ecc-root           – top-level ECC self-signed roots under artifacts/
#   tempo-cross        – anchored certs from artifacts/tempo/
#   artifact-self      – fallback bucket for self-signed certs
#   artifact-cross     – fallback bucket for anchored certs

pymod = import('python')
_py3 = pymod.find_installation('python3')

if _py3.found()
  _artifacts = meson.project_source_root() / 'artifacts'
  _helper    = meson.current_source_dir() / 'list_cert_pairs.py'

  _pairs = run_command(
    _py3, _helper, _artifacts,
    check           : false,
    capture         : true,
  )

  if _pairs.returncode() == 0 and _pairs.stdout().strip() != ''
    foreach _line : _pairs.stdout().strip().split('\n')
      _fields = _line.strip().split('|')
      if _fields.length() == 5
        _cert        = _fields[0]
        _anchor      = _fields[1]
        _suite       = _fields[2]
        _name        = _fields[3]
        _expected    = _fields[4]

        test(
          'artifact/' + _suite + '/' + _name,
          x509_verif,
          args    : [_cert, _anchor],
          suite   : 'artifact-' + _suite,
          timeout : 30,
          should_fail : _expected == 'fail',
        )
      endif
    endforeach
  endif

endif
