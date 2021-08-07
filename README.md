[![build](https://github.com/yiguihai/shadowsocks_install/actions/workflows/build.yml/badge.svg)](https://github.com/yiguihai/shadowsocks_install/actions/workflows/build.yml)   
更多介绍与教程请查看[wiki](https://github.com/yiguihai/shadowsocks_install/wiki)   
### 使用方法
安装脚本
```Shell
wget --no-check-certificate -O /usr/local/bin/ss-main https://github.com/yiguihai/shadowsocks_install/raw/dev/usr/bin/ss-main  
chmod +x /usr/local/bin/ss-main
```
安装脚本(CDN)
```Shell
wget --no-check-certificate -O /usr/local/bin/ss-main https://cdn.jsdelivr.net/gh/yiguihai/shadowsocks_install@dev/usr/bin/ss-main
chmod +x /usr/local/bin/ss-main
```
运行脚本
```Shell
ss-main
```
查看状态
```Shell
systemctl status ss-main
```
取消开机自启
```Shell
systemctl disable ss-main
```
<details open>
  <summary>更新记录</summary>
  <table>
    <caption><i><b>2021年08月07日 09:09:05</b></i></caption>
    <thead>
      <tr>
        <th>项目</th>
        <th>更新详情</th>
      </tr>
    </thead>
    <tbody>
      <tr><td><a href=usr/app>shadowsocks-android</a></td><td><a href=https://github.com/shadowsocks/shadowsocks-android/commit/02dfcee4c8fc6d5880ebac30f1954ce6f8a63a6c>Downgrade leanback-preference</a></td></tr>
    </tbody>
  </table>
</details>
