# Changelog

## [1.11.0](https://github.com/PeterMosmans/security-scripts/compare/1.10.0...1.11.0) (2021-11-30)

### Features

- enforce timeout for nikto
  ([d751eaa](https://github.com/PeterMosmans/security-scripts/commit/d751eaa1a215c0487c2ccdf5726f246a5dd39438))
- ensure that Python output is unbuffered
  ([83d7fdd](https://github.com/PeterMosmans/security-scripts/commit/83d7fdd75a8228a9f17a1e32a116af36fd431b8b))
- rewrite deprecated function names
  ([e4bfbec](https://github.com/PeterMosmans/security-scripts/commit/e4bfbec7b973684c9d054b0c26dc36559739e8d8))

## [1.10.0](https://github.com/PeterMosmans/security-scripts/compare/1.9.0...1.10.0) (2021-05-27)

### Features

- support file-based argugments
  ([e33a6eb](https://github.com/PeterMosmans/security-scripts/commit/e33a6eb9bd37f2384ae2891b85355e4c966fbd5f))

## [1.9.0](https://github.com/PeterMosmans/security-scripts/compare/v1.8.0...v1.9.0) (2021-04-15)

### Features

- add multiple options to separate HTTP checks
  ([c038d28](https://github.com/PeterMosmans/security-scripts/commit/c038d28ab1d8413957e2b543d3da4bf8b2d696e8))
- add support for testssl parameters
  ([df202c0](https://github.com/PeterMosmans/security-scripts/commit/df202c00670bd7429763ad90ddfc590c7b0ed80c))
- switch protocol when trying to analyze framework
  ([ed25f28](https://github.com/PeterMosmans/security-scripts/commit/ed25f286ee87d8a3cd1737d2379c958332064449))

### Bug Fixes

- change settings YAML syntax for tuning parameters
  ([beaea06](https://github.com/PeterMosmans/security-scripts/commit/beaea06fa1eed64fdecc933eead5811354fe8a31))
- ensure that testssl untrusted parameter is properly used
  ([02dc66d](https://github.com/PeterMosmans/security-scripts/commit/02dc66d47366d7740909f1a04008b7a703789751))

## [1.8.0](https://github.com/PeterMosmans/security-scripts/compare/v1.7.0...v1.8.0) (2020-09-18)

### Features

- add option to enforce SSL/TLS check
  ([b641f7a](https://github.com/PeterMosmans/security-scripts/commit/b641f7a78ab2d4579d016d8821ab3c6c3c6836c7))

### Bug Fixes

- ensure that a host contains a port key
  ([6083104](https://github.com/PeterMosmans/security-scripts/commit/6083104f28598f7ea71ccb557557c0e7bbebe0c9))

## [1.7.0](https://github.com/PeterMosmans/security-scripts/compare/v1.6.0...v1.7.0) (2020-08-24)

### Features

- generate alert when unexpected open port is found
  ([9cbc4a4](https://github.com/PeterMosmans/security-scripts/commit/9cbc4a458ece2a213d05cfd1ddd446c56ed1fb1c))
- **display_hosts:** add several new options
  ([6c7077e](https://github.com/PeterMosmans/security-scripts/commit/6c7077e9be6c0b7e6e9e35ef0c781b277d65bfb3))
- add display_results helper script
  ([6016cab](https://github.com/PeterMosmans/security-scripts/commit/6016cab79f6a6020929b6479dca10e6ad3e83206))
- improve displaying results, show unexpected open ports
  ([5f8a8af](https://github.com/PeterMosmans/security-scripts/commit/5f8a8aff01a86d66fb340f630f603e07a53d30ee))

### Bug Fixes

- ensure results are shown without specifying host
  ([0efe1c5](https://github.com/PeterMosmans/security-scripts/commit/0efe1c573c9a569b6ece19be9bdf2113c407ddee))

## [1.6.0](https://github.com/PeterMosmans/security-scripts/compare/v1.5.0...v1.6.0) (2020-08-06)

### Features

- add option to use exit code != 0 when alerts are detected
  ([ded66fa](https://github.com/PeterMosmans/security-scripts/commit/ded66fa26d8fc7141c709560383b505ce6d54ae8))
- support more Nikto parameters
  ([d5592cc](https://github.com/PeterMosmans/security-scripts/commit/d5592ccda17fcc2bcf4559245066e01d59755d88))

### Bug Fixes

- ensure that Control-C is properly handled
  ([8b7c2de](https://github.com/PeterMosmans/security-scripts/commit/8b7c2deeba1a2e5d30b6f4630319a0a2355134a4))
- ensure that settings file is not obligatory
  ([8698e9c](https://github.com/PeterMosmans/security-scripts/commit/8698e9c8ed50436455b28f64e5d7c95b503289ad))
- in debug mode, show options after all options have been parsed
  ([890054f](https://github.com/PeterMosmans/security-scripts/commit/890054f9ceaa89dca12bc98e307412db84ad424b))

## [1.5.0](https://github.com/PeterMosmans/security-scripts/compare/v1.4.0...v1.5.0) (2020-08-06)

### Features

- add support for YAML settings file
  ([b5d422a](https://github.com/PeterMosmans/security-scripts/commit/b5d422a623eb1cd594ab2676618294e79872821c))
- add YAML library requirement
  ([d6e3068](https://github.com/PeterMosmans/security-scripts/commit/d6e30688ee4bef8466f5a0d24931bcb5dcb4e8d3))

## [1.4.0](https://github.com/PeterMosmans/security-scripts/compare/v1.3.0...v1.4.0) (2020-08-03)

### Features

- add Dockerfile
  ([1deb82d](https://github.com/PeterMosmans/security-scripts/commit/1deb82db8021e2ee797e7c4b27d2a312019bfe0e))

### Bug Fixes

- change testssl.sh parameter
  ([1fc2f4d](https://github.com/PeterMosmans/security-scripts/commit/1fc2f4db9f01d50c8f43a6e2b38ec2aa6b6a5f8c))

## [1.3.0](https://github.com/PeterMosmans/security-scripts/compare/v1.2.0...v1.3.0) (2020-06-24)

### Features

- add support to keep or discard line endings from logfiles
  ([c87c07f](https://github.com/PeterMosmans/security-scripts/commit/c87c07f35603f2304e499d791bd5dbbaec93ed10))
- optimize WPscan by enforcing update and not showing banner
  ([b855bf4](https://github.com/PeterMosmans/security-scripts/commit/b855bf4a46f2936db2a638d4732c1a536d3eae2e))

### Bug Fixes

- ensure correct type is passed when parsing logs
  ([7c876f8](https://github.com/PeterMosmans/security-scripts/commit/7c876f8cba71a6e850bae4e40082e4a6cb8b39ea))
- ensure proper logging when not compacting strings
  ([ed2c84c](https://github.com/PeterMosmans/security-scripts/commit/ed2c84c62e734f3bd77cc417b74a4f40bd7845bc))
- ensure that nmap logfile gets properly concatenated into log
  ([8b5a633](https://github.com/PeterMosmans/security-scripts/commit/8b5a6331e1588f6d1bbd0798708687b622b3f44a))
- ensure universal similar line endings
  ([feb6ab0](https://github.com/PeterMosmans/security-scripts/commit/feb6ab0282f6962e271c41463ec7b090dc0b3b89))

## [1.2.0](https://github.com/PeterMosmans/security-scripts/compare/v1.1.0...v1.2.0) (2020-05-29)

### Features

- add more nmap alerts and info
  ([6371495](https://github.com/PeterMosmans/security-scripts/commit/637149586d13dc30e793a47100f67d38533e6fb2))
- add more nmap info strings
  ([7aa7045](https://github.com/PeterMosmans/security-scripts/commit/7aa704562585fba37b909f678e84630e161c9c47))
- remove more prepended characters before alerts / info
  ([cdd5cc9](https://github.com/PeterMosmans/security-scripts/commit/cdd5cc940a1fac056ec7b93f0e3b1528dc357cab))
- store obtained information in new info value
  ([81a6fbd](https://github.com/PeterMosmans/security-scripts/commit/81a6fbdd810549930dff235b342412693cd647bf))

### Bug Fixes

- move nmap alert strings to info
  ([3c2c281](https://github.com/PeterMosmans/security-scripts/commit/3c2c28135837d206802522b4c4e2d889ec7b007d))

## [1.1.0](https://github.com/PeterMosmans/security-scripts/compare/v1.0.0...v1.1.0) (2020-05-28)

### Features

- add initial version of showing obtained nmap plugin info
  ([91b039b](https://github.com/PeterMosmans/security-scripts/commit/91b039b831642947241d9332819581f2e0523f25))
- add more nmap alerts
  ([f45224e](https://github.com/PeterMosmans/security-scripts/commit/f45224eac7ac124867cf431460f175136ee99148))
- add testssl.sh alert
  ([e5536e6](https://github.com/PeterMosmans/security-scripts/commit/e5536e6725073813ffa77a1927cd8adf16e9152f))
- add testssl.sh alerts
  ([f3bf2e6](https://github.com/PeterMosmans/security-scripts/commit/f3bf2e69062ba34b0aa712d3705a56d5a2bb97d9))
- enforce nikto to run non-interactive
  ([0adf0b9](https://github.com/PeterMosmans/security-scripts/commit/0adf0b9d71db631f81c63e263539b959fa84566d))
- remove Python2 compatibility (simplify code)
  ([57e62cb](https://github.com/PeterMosmans/security-scripts/commit/57e62cb46317d06d7ac07c1092aa520669fdd893))
- store version string of tool being used
  ([7e8af96](https://github.com/PeterMosmans/security-scripts/commit/7e8af96363f7ac7169d467e8ea7de4505500485a))
- use version first, to enable better sorting
  ([3692207](https://github.com/PeterMosmans/security-scripts/commit/36922076b6b2738e0550ead84d7dc306c96604b4))

### Bug Fixes

- ensure no raw line endings are logged
  ([8c3d981](https://github.com/PeterMosmans/security-scripts/commit/8c3d9813b9761b3dea6454bbc91101e0e1bae005))
- ensure that line endings are kept when adding logs
  ([f79dbe6](https://github.com/PeterMosmans/security-scripts/commit/f79dbe63739fc6a18b369ce973f7cdf3d2d0a4f5))
- ensure that logfile strings are properly read
  ([10e5e4f](https://github.com/PeterMosmans/security-scripts/commit/10e5e4ff796ecf8739292d21f879e43c82c459b0))
- ensure that nmap command line isn't flagged as alert
  ([a093cad](https://github.com/PeterMosmans/security-scripts/commit/a093cad1afaf93f183b0cbdeb490f4bc341e3d6b))
- ensure that wpscan ignores any server-supplied redirects
  ([cc19dc3](https://github.com/PeterMosmans/security-scripts/commit/cc19dc397e75818f323a63e0d294065e8f2f4f40))
- properly read and append existing logfiles
  ([aae922a](https://github.com/PeterMosmans/security-scripts/commit/aae922a6104505a9ec1d7b1ca2f7354e0d1f9d6e))
- remove obsolete inheritance from object
  ([e231d27](https://github.com/PeterMosmans/security-scripts/commit/e231d27a946495f775b76b8cab08b7142ee515b5))

## [1.0.0](https://github.com/PeterMosmans/security-scripts/compare/v0.44.2...v1.0.0) (2020-05-28)

### Features

- enable JSON output
  ([018d1a9](https://github.com/PeterMosmans/security-scripts/commit/018d1a998f34584a56d884a6f12ff5b15025c80b))
- filter out unnecessary characters in alert string
  ([49b3fea](https://github.com/PeterMosmans/security-scripts/commit/49b3feafc970fbef6c1a81b0854343046329eb84))
- log alert per port instead of generic lines
  ([3ea2241](https://github.com/PeterMosmans/security-scripts/commit/3ea22411e8eacac886c6f8d1fd4eb8f625e233b7))
- log port number with alert line
  ([6c180b6](https://github.com/PeterMosmans/security-scripts/commit/6c180b6d0bfd1455fca73b368be8719563e8f60a))
- parse port number to add with nmap alert
  ([9a1daef](https://github.com/PeterMosmans/security-scripts/commit/9a1daefd62aff6cb4d4beb731e58854620320b01))
- record all ciphers when performing testssl.sh
  ([19d05f4](https://github.com/PeterMosmans/security-scripts/commit/19d05f4feda1c52c55d4f0e24a02abd7f951b910))
- reduce default maximum scan time from 20 to to 10 minutes
  ([fb2c73e](https://github.com/PeterMosmans/security-scripts/commit/fb2c73e6ff5432fb1c00c971a21f03fbb5ceb25b))
- remove whitespace and superfluous line endings in alerts
  ([264ccb4](https://github.com/PeterMosmans/security-scripts/commit/264ccb45cc43cdafc256045639a4680787693a1c))

### Bug Fixes

- properly split lines in logfiles and tool outputs
  ([02c490e](https://github.com/PeterMosmans/security-scripts/commit/02c490e5ac86597f4cb0fc7ee956f296135ee8e1))
- use format strings and properly show port number
  ([e832c6e](https://github.com/PeterMosmans/security-scripts/commit/e832c6e8db2552d07b3459132687ba223900e73d))

### [0.44.2](https://github.com/PeterMosmans/security-scripts/compare/v0.44.1...v0.44.2) (2020-05-25)

### Bug Fixes

- make process handler Python3 proof
  ([638bc6e](https://github.com/PeterMosmans/security-scripts/commit/638bc6e3ebd5edc5fdd597708e34493c4f76f6ad))

### 0.44.1 (2020-03-04)

### Bug Fixes

- allow program to continue with --no-portscan and without nmap
  ([9e1eaed](https://github.com/PeterMosmans/security-scripts/commit/9e1eaedac73c4814292156642ceda40c2f9bf7f8))
- respect --dry-run when performing --check-redirect
  ([294d364](https://github.com/PeterMosmans/security-scripts/commit/294d364604031b9feba63909d24101115afc29a3))
- setting umask only when necessary
  ([7fbbddd](https://github.com/PeterMosmans/security-scripts/commit/7fbbdddbd0a4232bfcb0e1981a56a75ffbcdc5ef))
- still use nmap as tool if --no-portscan is specified
  ([85ce908](https://github.com/PeterMosmans/security-scripts/commit/85ce908e9c3459b2d828cd13efb62f62d32752a8))
- typo
  ([9fa9b91](https://github.com/PeterMosmans/security-scripts/commit/9fa9b916575b6b6651c02ddd2c31285acf59511f))
- use specified port numbers even when nmap is not present
  ([bf83792](https://github.com/PeterMosmans/security-scripts/commit/bf83792c8db1fabba10491ee32a3e990a4896554))
- use specified ports when not performing portscan
  ([cda920c](https://github.com/PeterMosmans/security-scripts/commit/cda920c59e4144dcba91ad49594217d124fe3dec))
