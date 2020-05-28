# Changelog

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
