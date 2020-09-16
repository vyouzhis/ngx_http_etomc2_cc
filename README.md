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
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/vyouzhi">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
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

* [关于该项目(About the Project)](#about-the-project)
  * [依赖关系(Built With)](#built-with)
* [起始(Getting Started)](#getting-started)
  * [编译安装(Installation)](#installation)
* [Usage](#usage)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)



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
./configure --add-module=../ngx_http_etomc2_cc --with-http_ssl_module --with-stream_ssl_module
gmake
gmake install
```



<!-- USAGE EXAMPLES -->
## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/vyouzhis/ngx_http_etomc2_cc/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

Your Name - [@your_twitter](https://twitter.com/your_username) - email@example.com

Project Link: [https://github.com/your_username/repo_name](https://github.com/your_username/repo_name)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [GitHub Emoji Cheat Sheet](https://www.webpagefx.com/tools/emoji-cheat-sheet)
* [Img Shields](https://shields.io)
* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Pages](https://pages.github.com)
* [Animate.css](https://daneden.github.io/animate.css)
* [Loaders.css](https://connoratherton.com/loaders)
* [Slick Carousel](https://kenwheeler.github.io/slick)
* [Smooth Scroll](https://github.com/cferdinandi/smooth-scroll)
* [Sticky Kit](http://leafo.net/sticky-kit)
* [JVectorMap](http://jvectormap.com)
* [Font Awesome](https://fontawesome.com)





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
[linkedin-url]: https://linkedin.com/in/vyouzhis
[product-screenshot]: images/screenshot.png
