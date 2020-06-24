# Changelog

## [1.3.0](https://github.com/PeterMosmans/security-scripts/compare/v1.2.0...v1.3.0) (2020-06-24)


### Features

* add support to keep or discard line endings from logfiles ([c87c07f](https://github.com/PeterMosmans/security-scripts/commit/c87c07f35603f2304e499d791bd5dbbaec93ed10))
* optimize WPscan by enforcing update and not showing banner ([b855bf4](https://github.com/PeterMosmans/security-scripts/commit/b855bf4a46f2936db2a638d4732c1a536d3eae2e))


### Bug Fixes

* ensure correct type is passed when parsing logs ([7c876f8](https://github.com/PeterMosmans/security-scripts/commit/7c876f8cba71a6e850bae4e40082e4a6cb8b39ea))
* ensure proper logging when not compacting strings ([ed2c84c](https://github.com/PeterMosmans/security-scripts/commit/ed2c84c62e734f3bd77cc417b74a4f40bd7845bc))
* ensure that nmap logfile gets properly concatenated into log ([8b5a633](https://github.com/PeterMosmans/security-scripts/commit/8b5a6331e1588f6d1bbd0798708687b622b3f44a))
* ensure universal similar line endings ([feb6ab0](https://github.com/PeterMosmans/security-scripts/commit/feb6ab0282f6962e271c41463ec7b090dc0b3b89))

## [1.2.0](https://github.com/PeterMosmans/security-scripts/compare/v1.1.0...v1.2.0) (2020-05-29)


### Features

* add more nmap alerts and info ([6371495](https://github.com/PeterMosmans/security-scripts/commit/637149586d13dc30e793a47100f67d38533e6fb2))
* add more nmap info strings ([7aa7045](https://github.com/PeterMosmans/security-scripts/commit/7aa704562585fba37b909f678e84630e161c9c47))
* remove more prepended characters before alerts / info ([cdd5cc9](https://github.com/PeterMosmans/security-scripts/commit/cdd5cc940a1fac056ec7b93f0e3b1528dc357cab))
* store obtained information in new info value ([81a6fbd](https://github.com/PeterMosmans/security-scripts/commit/81a6fbdd810549930dff235b342412693cd647bf))


### Bug Fixes

* move nmap alert strings to info ([3c2c281](https://github.com/PeterMosmans/security-scripts/commit/3c2c28135837d206802522b4c4e2d889ec7b007d))

## [1.1.0](https://github.com/PeterMosmans/security-scripts/compare/v1.0.0...v1.1.0) (2020-05-28)


### Features

* add initial version of showing obtained nmap plugin info ([91b039b](https://github.com/PeterMosmans/security-scripts/commit/91b039b831642947241d9332819581f2e0523f25))
* add more nmap alerts ([f45224e](https://github.com/PeterMosmans/security-scripts/commit/f45224eac7ac124867cf431460f175136ee99148))
* add testssl.sh alert ([e5536e6](https://github.com/PeterMosmans/security-scripts/commit/e5536e6725073813ffa77a1927cd8adf16e9152f))
* add testssl.sh alerts ([f3bf2e6](https://github.com/PeterMosmans/security-scripts/commit/f3bf2e69062ba34b0aa712d3705a56d5a2bb97d9))
* enforce nikto to run non-interactive ([0adf0b9](https://github.com/PeterMosmans/security-scripts/commit/0adf0b9d71db631f81c63e263539b959fa84566d))
* remove Python2 compatibility (simplify code) ([57e62cb](https://github.com/PeterMosmans/security-scripts/commit/57e62cb46317d06d7ac07c1092aa520669fdd893))
* store version string of tool being used ([7e8af96](https://github.com/PeterMosmans/security-scripts/commit/7e8af96363f7ac7169d467e8ea7de4505500485a))
* use version first, to enable better sorting ([3692207](https://github.com/PeterMosmans/security-scripts/commit/36922076b6b2738e0550ead84d7dc306c96604b4))


### Bug Fixes

* ensure no raw line endings are logged ([8c3d981](https://github.com/PeterMosmans/security-scripts/commit/8c3d9813b9761b3dea6454bbc91101e0e1bae005))
* ensure that line endings are kept when adding logs ([f79dbe6](https://github.com/PeterMosmans/security-scripts/commit/f79dbe63739fc6a18b369ce973f7cdf3d2d0a4f5))
* ensure that logfile strings are properly read ([10e5e4f](https://github.com/PeterMosmans/security-scripts/commit/10e5e4ff796ecf8739292d21f879e43c82c459b0))
* ensure that nmap command line isn't flagged as alert ([a093cad](https://github.com/PeterMosmans/security-scripts/commit/a093cad1afaf93f183b0cbdeb490f4bc341e3d6b))
* ensure that wpscan ignores any server-supplied redirects ([cc19dc3](https://github.com/PeterMosmans/security-scripts/commit/cc19dc397e75818f323a63e0d294065e8f2f4f40))
* properly read and append existing logfiles ([aae922a](https://github.com/PeterMosmans/security-scripts/commit/aae922a6104505a9ec1d7b1ca2f7354e0d1f9d6e))
* remove obsolete inheritance from object ([e231d27](https://github.com/PeterMosmans/security-scripts/commit/e231d27a946495f775b76b8cab08b7142ee515b5))

## [1.0.0](https://github.com/PeterMosmans/security-scripts/compare/v0.44.2...v1.0.0) (2020-05-28)


### Features

* enable JSON output ([018d1a9](https://github.com/PeterMosmans/security-scripts/commit/018d1a998f34584a56d884a6f12ff5b15025c80b))
* filter out unnecessary characters in alert string ([49b3fea](https://github.com/PeterMosmans/security-scripts/commit/49b3feafc970fbef6c1a81b0854343046329eb84))
* log alert per port instead of generic lines ([3ea2241](https://github.com/PeterMosmans/security-scripts/commit/3ea22411e8eacac886c6f8d1fd4eb8f625e233b7))
* log port number with alert line ([6c180b6](https://github.com/PeterMosmans/security-scripts/commit/6c180b6d0bfd1455fca73b368be8719563e8f60a))
* parse port number to add with nmap alert ([9a1daef](https://github.com/PeterMosmans/security-scripts/commit/9a1daefd62aff6cb4d4beb731e58854620320b01))
* record all ciphers when performing testssl.sh ([19d05f4](https://github.com/PeterMosmans/security-scripts/commit/19d05f4feda1c52c55d4f0e24a02abd7f951b910))
* reduce default maximum scan time from 20 to to 10 minutes ([fb2c73e](https://github.com/PeterMosmans/security-scripts/commit/fb2c73e6ff5432fb1c00c971a21f03fbb5ceb25b))
* remove whitespace and superfluous line endings in alerts ([264ccb4](https://github.com/PeterMosmans/security-scripts/commit/264ccb45cc43cdafc256045639a4680787693a1c))


### Bug Fixes

* properly split lines in logfiles and tool outputs ([02c490e](https://github.com/PeterMosmans/security-scripts/commit/02c490e5ac86597f4cb0fc7ee956f296135ee8e1))
* use format strings and properly show port number ([e832c6e](https://github.com/PeterMosmans/security-scripts/commit/e832c6e8db2552d07b3459132687ba223900e73d))

### [0.44.2](https://github.com/PeterMosmans/security-scripts/compare/v0.44.1...v0.44.2) (2020-05-25)


### Bug Fixes

* make process handler Python3 proof ([638bc6e](https://github.com/PeterMosmans/security-scripts/commit/638bc6e3ebd5edc5fdd597708e34493c4f76f6ad))

### 0.44.1 (2020-03-04)


### Bug Fixes

* allow program to continue with --no-portscan and without nmap ([9e1eaed](https://github.com/PeterMosmans/security-scripts/commit/9e1eaedac73c4814292156642ceda40c2f9bf7f8))
* respect --dry-run when performing --check-redirect ([294d364](https://github.com/PeterMosmans/security-scripts/commit/294d364604031b9feba63909d24101115afc29a3))
* setting umask only when necessary ([7fbbddd](https://github.com/PeterMosmans/security-scripts/commit/7fbbdddbd0a4232bfcb0e1981a56a75ffbcdc5ef))
* still use nmap as tool if --no-portscan is specified ([85ce908](https://github.com/PeterMosmans/security-scripts/commit/85ce908e9c3459b2d828cd13efb62f62d32752a8))
* typo ([9fa9b91](https://github.com/PeterMosmans/security-scripts/commit/9fa9b916575b6b6651c02ddd2c31285acf59511f))
* use specified port numbers even when nmap is not present ([bf83792](https://github.com/PeterMosmans/security-scripts/commit/bf83792c8db1fabba10491ee32a3e990a4896554))
* use specified ports when not performing portscan ([cda920c](https://github.com/PeterMosmans/security-scripts/commit/cda920c59e4144dcba91ad49594217d124fe3dec))
