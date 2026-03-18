artifacts = files(
    'artifacts/all-gosts-self-signed/*.pem',
    'artifacts/exotic/ED25519/*.pem',
    'artifacts/exotic/ED448/*.pem',
    'artifacts/exotic/SM2-SM3/*.pem',
    'artifacts/exotic/gost-root/*.pem',
    'artifacts/all-gosts-sig2012/*.pem',
    'artifacts/all-gosts/*.pem',
    'artifacts/tempo/*.pem',
)

install_data(artifacts, install_dir: 'share/x509-verif/artifacts')
