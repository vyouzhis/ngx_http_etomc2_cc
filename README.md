<!--
*** Thanks for checking out this README Template. If you have a suggestion that would
*** make this better, please fork the repo and create a pull request or simply open
*** an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
-->





<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/vyouzhi">
    <img src="https://avatars2.githubusercontent.com/u/5832145?s=400&u=e1923037c2831a3de8e1bb5b3305c1434b85981d&v=4" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">ngx_http_etomc2_cc</h3>

  <p align="center">
    ngx_http_etomc2_cc is nginx module Anti attack cc!
    <br />
    ngx_http_etomc2_cc 是 nginx 一个智能防护 CC 攻击的模块插件
    <br />
    <a href="https://github.com/vyouzhis/ngx_http_etomc2_cc"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/vyouzhis/ngx_http_etomc2_cc">View Demo</a>
    ·
    <a href="https://github.com/vyouzhis/ngx_http_etomc2_cc/issues">Report Bug</a>
    ·
    <a href="https://github.com/vyouzhis/ngx_http_etomc2_cc/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
## 栏目(Table of Contents)

* [关于该项目(About the Project)](#关于该项目about-the-project)
  * [依赖关系(Built With)](#依赖关系built-with)
* [起始(Getting Started)](#起始getting-started)
  * [编译安装(Installation)](#编译安装installation)
* [配置(Usage)](#配置usage)
* [调试(Review)](#调试Review)
* [License](#license)
* [联系(Contact)](#联系contact)



<!-- ABOUT THE PROJECT -->
## 关于该项目(About the Project)

主要分析网站访问者的用户行为.不同的访问者在浏览某一个网站的时候，都会产生不同的用户行为。目前暂把该行为分成三类：

用户行为:
* 正常的访问者：一般的访问者都是从首页进入，之后综横分开访问不同的内页。
* 恶意的访问者：会通过大量的IP同时访问某一个页面或API，从而造成服务器的内存及CPU消耗，而形成攻击。
* 单点访问者：这种访问基本上都是流失型，只会访问次数较少的，产生不了用户行为，就消失了。

目前本插件模块，可以快速分析有恶意的访问者，从而可以进行拦截。

### 依赖关系(Built With)
需要用到的软件版本.
* [nginx](http://nginx.org/en/download.html)
* [ngx_http_etomc2_cc](https://github.com/vyouzhis/ngx_http_etomc2_cc)



<!-- GETTING STARTED -->
## 起始(Getting Started)

需要下载以下的文件.

### 编译安装(Installation)

1. 在这儿选择 nginx 的版本 [http://nginx.org/download/nginx-1.18.0.tar.gz](http://nginx.org/en/download.html)
2. 下载nginx
```sh
wget http://nginx.org/download/nginx-1.18.0.tar.gz
```
3. 解压
```sh
tar -zxvf nginx-1.18.0.tar.gz
```
4. git clone ngx_http_etomc2_cc
```JS
git clone https://github.com/vyouzhis/ngx_http_etomc2_cc.git
```
5. 编译安装
```sh
./configure --add-module=../ngx_http_etomc2_cc --with-http_ssl_module
gmake
gmake install
```



<!-- USAGE EXAMPLES -->
## 配置(Usage)
| 指令        | 区域           | 说明  |
| ------------- |:-------------:| -----:|
| ET2CCEnable      | http | 是否启用本防CC模块:on or off |
| et2_shm_size      | http      |   本防CC 模块使用的内存 |
| et2_cc_level | server      |    本防CC 等级,值: [1-5]  |
|et2_cc_itemize | server     | 当前的server是否启用防CC模块:on or off |
|et2_cc_return_status | server| 当成功拦截后，返回的状态码,默认为:444 |


_参考配置 [nginx example conf](https://github.com/vyouzhis/ngx_http_etomc2_cc/tree/master/doc/example_nginx.conf)_

<!-- Review -->
## 调试(Review)
采用一个bash shell 进行测试
```sh
cat hack.sh
#! /bin/sh
#
# hack.sh
# Copyright (C) 2020 vyouzhi <vyouzhi@localhost.localdomain>
#
# Distributed under terms of the MIT license.
#


for n in {1..15}
do
    echo $n
    ab -n 300 -c 30  -H "User-Agent: abc$n"  http://192.168.2.127/php.php&
done

```
nginx 的 access 日志
```
tail -50 ../logs/access.log
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc15"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc12"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc14"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc6"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc15"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc14"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc6"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc14"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc6"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc14"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc6"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc6"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc6"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10"
192.168.2.149 - - [17/Sep/2020:17:55:23 +0800] "GET /php.php HTTP/1.0" 444 0 "-" "abc10
```


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

vyouzhi - [@github](https://github.com/vyouzhis/ngx_http_etomc2_cc) - vouzhi@gmail.com

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/vyouzhis/ngx_http_etomc2_cc.svg?style=flat-square
[contributors-url]: https://github.com/vyouzhis/ngx_http_etomc2_cc/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/vyouzhis/ngx_http_etomc2_cc.svg?style=flat-square
[forks-url]: https://github.com/vyouzhis/ngx_http_etomc2_cc/network/members
[stars-shield]: https://img.shields.io/github/stars/vyouzhis/ngx_http_etomc2_cc.svg?style=flat-square
[stars-url]: https://github.com/vyouzhis/ngx_http_etomc2_cc/stargazers
[issues-shield]: https://img.shields.io/github/issues/vyouzhis/ngx_http_etomc2_cc.svg?style=flat-square
[issues-url]: https://github.com/vyouzhis/ngx_http_etomc2_cc/issues
[license-shield]: https://img.shields.io/github/license/vyouzhis/ngx_http_etomc2_cc.svg?style=flat-square
[license-url]: https://github.com/vyouzhis/ngx_http_etomc2_cc/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=flat-square&logo=linkedin&colorB=555
[product-screenshot]: images/screenshot.png
