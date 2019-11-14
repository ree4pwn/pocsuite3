# pocsuite3

[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/knownsec/Pocsuite/master/docs/COPYING) [![Twitter](https://img.shields.io/badge/twitter-@seebug-blue.svg)](https://twitter.com/seebug_team) [![build](https://api.travis-ci.org/knownsec/pocsuite3.svg)](https://travis-ci.org/knownsec/pocsuite3)

## Fork from knownsec/pocsuite3

More basic informatin please visit [pocsuite3](https://github.com/knownsec/pocsuite3).

## Useage

默认情况下`attack`是上传一句话木马，特殊情况会在`show info`中说明。

## PoC Collection

- [ ] Discuz
    - [ ] discuzX_ssv_91879_ssrf
    - [X] discuz_ssv_93726_rce
- [ ] Drupal
    - [ ] drupal_cve_2017_6229_rce
    - [X] drupal_cve_2018_7600_rce
    - [ ] drupal_cve_2019_6339_rce
- [ ] ThinkPHP
    - [X] thinkphp_rce 5.0.0-22 5.1.0-30 RCE
    - [ ] thinkphp_rce2 5.0.0-23 RCE
- [ ] Weblogic
- [ ] Struts2
    - [X] struts2_s2_001_rce
- [ ] WordPress
    - [X] wordpress_cve_2016_10033_rce

## TODO

- [X] 在POC info显示中增加已测试环境
- [ ] 增加默认自定义header功能
- [X] 增加pocDesc红色高亮
- [ ] 与[webshell-venom](https://github.com/yzddmr6/webshell-venom)结合