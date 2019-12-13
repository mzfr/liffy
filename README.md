[![GitSpo Mentions](https://gitspo.com/badges/mentions/mzfr/liffy?style=flat-square)](https://gitspo.com/mentions/mzfr/liffy)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/mzfr/liffy/graphs/commit-activity)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/tools.html#Liffy)

[![Packaging status](https://repology.org/badge/vertical-allrepos/liffy.svg)](https://repology.org/project/liffy/versions)

<h1 align="center">
  <br>
  <a href="https://github.com/mzfr/liffy"><img src="Images/Liffy-logo.png" alt="liffy"></a>
  <br>
</h1>

<h4 align="center">LFI Exploitation tool</h4>

![liffy in action](Images/liffy.png)

<p align="center">
  <a href="https://github.com/mzfr/liffy/wiki">liffy Wiki</a> •
  <a href="https://github.com/mzfr/liffy/wiki/Usage">Usage</a> •
  <a href="https://github.com/mzfr/liffy/wiki/Installation">Installation</a> •
</p>

A little python tool to perform Local file inclusion.

Liffy v2.0 is the improved version of [liffy](https://github.com/hvqzao/liffy) which was originally created by [rotlogix/liffy](https://github.com/rotlogix/liffy). The latter is no longer available and the former hasn't seen any development for a long time.


## Main feature

  - data:// for code execution
  - expect:// for code execution
  - input:// for code execution
  - filter:// for arbitrary file reads
  - /proc/self/environ for code execution in CGI mode
  - Apache access.log poisoning
  - Linux auth.log SSH poisoning
  - Direct payload delivery with no stager
  - Support for absolute and relative path traversal
  - Support for cookies for authentication

## Documentation

* [Installation](https://github.com/mzfr/liffy/wiki/Installation)
* [Usage](https://github.com/mzfr/liffy/wiki/Usage)

## Contribution

* Suggest a feature
  - Like any other technique to exploit LFI

* Report a bug
* Fix something and open a pull request

In any case feel free to open an issue

## Credits

All the exploitation techniques are taken from [liffy](https://github.com/hvqzao/liffy)

Logo for this project is taken from [renderforest](https://www.renderforest.com/)

## Support

If you'd like you can buy me some coffee:

<a href="https://www.buymeacoffee.com/mzfr" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" style="height: 51px !important;width: 217px !important;" ></a>
