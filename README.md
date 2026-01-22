### 个人自用配置，国内规则较少，仅包含部分常用网站，可能不适合你使用，请自行斟酌。
#### 自用Clash分流规则集合及配置文件，分流规则收集自网络，个人整理。

 rule-providers：俗称规则集合，通过它，可以引用不同类型的在线规则集 （URL），clash 就能自动根据访问目标是否在规则集中，然后匹配到对应的规则，从而选择代理/节点或者本地网络进行访问。简单地说，rule-provider 能让在线的规则集，下载到本地供我们使用，配合rules/RULE-SET使用。

 proxy-providers：俗称代理集合，通过它，可以提取指定 Clash订阅链接或者本地配置文件中的proxies字段中的所有内容。简单地说，proxy-providers 帮助我们提取订阅链接或者配置文件中所包含的节点信息，到当前配置文件中供我们使用（不使用机场/原来的分流规则）

##### 分流规则（策略）看个人使用习惯，适合增加/减少，无特别要求，使用GFW列表规则走代理，其它直连即可。
### 下方示例配置适用于使用各个clash内核的客户端，包括苹果的Stash，考虑到配置文件通用性，故没有使用meta内核的特性。
#### 在proxy-providers下的url填入clash订阅即可使用（节点筛选部分请根据自己机场节点名关键词书写)，规则集(rule-providers)及proxy-groups(策略或代理组)可按个人需求增减

```mixed-port: 7890 # 本地混合代理(http和socks5合并）端口
mode: rule # clash工作模式（rule/global/direct,meta暂不支持script）
ipv6: true # ip6开关，当为false时，停止解析hostanmes为ip6地址
log-level: info # 日志等级 （info/warning/error/debug/silent）
allow-lan: false # 是否允许局域网链接(false/true)
unified-delay: false # 統一延遲
tcp-concurrent: true
# ⬇️⬇️控制面板⬇️⬇️
external-controller: 127.0.0.1:9236
secret: "xvs32HDRY"
external-ui: ui
external-ui-name: metacubexd
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
# ⬇️⬇️GEO模式
geodata-mode: true
geodata-loader: standard
geo-auto-update: true
geo-update-interval: 168
# ⬇️⬇️自定GEO下载地址⬇️⬇️
geox-url:
  geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"
  geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
  #mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"
  #asn: "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb"
# ⬇️⬇️匹配进程 always/strict/off⬇️⬇️
find-process-mode: strict
#global-client-fingerprint: chrome
#keep-alive-idle: 600
#keep-alive-interval: 30

clash-for-android: {append-system-dns: false}
profile: {store-selected: true, store-fake-ip: true}
hosts: {mtalk.google.com: 108.177.97.188}
sniffer:
  enable: true
  #force-dns-mapping: true #对 redir-host 类型识别的流量进行强制嗅探
  parse-pure-ip: true #对所有未获取到域名的流量进行强制嗅探
  #override-destination: false #是否使用嗅探结果作为实际访问，默认为 true
  sniff:
    TLS: {ports: [1-65535], override-destination: true}
    HTTP: {ports: [1-65535], override-destination: true}
    QUIC: {ports: [443, 8443]}
  force-domain: #强制进行嗅探的域名列表，使用域名通配⬇️⬇️
    - +.v2ex.com
  skip-domain: #跳过嗅探的域名列表，使用域名通配⬇️⬇️
    - Mijia Cloud
    #skip-src-address:  #跳过嗅探的来源 IP 段列表⬇️⬇️
    #- 192.168.55.211/32
    #skip-dst-address:  #跳过嗅探的目标 IP 段列表⬇️⬇️
    #- 192.168.55.201/32
#⬇️⬇️bypass：绕过Clash 系统代理⬇️⬇️
bypass: [<local>, localhost, 127.*, 10.*, 172.16.*, 172.17.*, 172.18.*, 172.19.*, 172.20.*, 172.21.*, 172.22.*, 172.23.*, 172.24.*, 172.25.*, 172.26.*, 172.27.*, 172.28.*, 172.29.*, 172.30.*, 172.31.*, '*.163.com', '*.126.com', '*.126.net', 'music.163.com', '*.music.126.net', '*.msftncsi.com', '*.kuwo.cn', '*.iqiyi.com', 192.168.*]
  
dns:
  enable: true
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  listen: 127.0.0.1:1853
  
  #⬇️默认dns, 用于解析域名类DNS的域名，只允许ip⬇️
  default-nameserver: ['223.5.5.5', '119.29.29.29']
  
  #⬇️默认的域名解析器，如不配置 fallback/proxy-server-nameserver , 则所有域名都由 nameserver 解析⬇️
  nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query']
  
  #⬇️代理域名解析器，仅用于解析代理的域名⬇️
  proxy-server-nameserver: ['https://dns.alidns.com/dns-query']
  
  #⬇️后备域名解析器（可选项）），一般情况下使用境外 DNS, 保证结果可信，配置 fallback后默认启用 fallback-filter，geoip-code为 cn⬇️⬇️
  #fallback: ['https://1.1.1.1/dns-query', 'https://dns.twnic.tw/dns-query', 'https://doh.dns.sb/dns-query', 'https://dns.cloudflare.com/dns-query']
  
  # ⬇️在以下列表的域名将不会被解析为 fake ip，这些域名相关的解析请求将会返回它们真实的 IP 地址⬇️
  fake-ip-filter: ['*.lan', '*.localdomain', '*.example', '*.invalid', '*.localhost', '*.test', '*.local', '*.home.arpa', time.*.com, time.*.gov, time.*.edu.cn, time.*.apple.com, time1.*.com, time2.*.com, time3.*.com, time4.*.com, time5.*.com, time6.*.com, time7.*.com, ntp.*.com, ntp1.*.com, ntp2.*.com, ntp3.*.com, ntp4.*.com, ntp5.*.com, ntp6.*.com, ntp7.*.com, '*.time.edu.cn', '*.ntp.org.cn', +.pool.ntp.org, time1.cloud.tencent.com, stun.*.*, stun.*.*.*, swscan.apple.com, mesu.apple.com, music.163.com, '*.music.163.com', '*.126.net', musicapi.taihe.com, music.taihe.com, songsearch.kugou.com, trackercdn.kugou.com, '*.kuwo.cn', api-jooxtt.sanook.com, api.joox.com, y.qq.com, '*.y.qq.com', streamoc.music.tc.qq.com, mobileoc.music.tc.qq.com, isure.stream.qqmusic.qq.com, dl.stream.qqmusic.qq.com, aqqmusic.tc.qq.com, amobile.music.tc.qq.com, localhost.ptlogin2.qq.com, '*.msftconnecttest.com', '*.msftncsi.com', '*.xiami.com', '*.music.migu.cn', music.migu.cn, +.wotgame.cn, +.wggames.cn, +.wowsgame.cn, +.wargaming.net, '*.*.*.srv.nintendo.net', '*.*.stun.playstation.net', '+.playstation.com', '+.playstation.net', '+.xboxlive.com', '+.microsoft.com' , xbox.*.*.microsoft.com, '*.*.xboxlive.com', '*.ipv6.microsoft.com', teredo.*.*.*, teredo.*.*, speedtest.cros.wr.pvp.net, +.jjvip8.com, www.douyu.com, activityapi.huya.com, activityapi.huya.com.w.cdngslb.com, www.bilibili.com, api.bilibili.com, a.w.bilicdn1.com, discfan.net, discfan.xyz, pt.0ff.cc]
    
  #⬇️后备域名解析器筛选，满足条件的将使用 fallback结果或只使用 fallback解析⬇️
  #fallback-filter: {geoip: true, geoip-code: CN, ipcidr: [240.0.0.0/4, 0.0.0.0/32, 127.0.0.1/32], domain: ['+.facebook.com', '+.twitter.com', '+.google.com', '+.googleapis.com', '+.youtube.com']}  
proxy-providers:
  Sub1:
    type: http
    path: ./providers/proxy/Sub1.yaml
    url: "https://......"
    interval: 864000
    override:
      proxy-name:
        - pattern: "trojan"
          target: ""
    health-check:
      enable: true
      url: "https://i.ytimg.com/generate_204"
      interval: 3600
    #filter: "(英国.*SS|SS.*英国)"  #筛选同时包"含SS和英国" 的节点
    filter: "🇬🇧|英国|香港|台湾|日本|新加坡|狮城|美国"     
    benchmark-url: https://i.ytimg.com/generate_204
  Sub2:
    type: http
    path: ./providers/proxy/Sub2.yaml
    url: "https://....."
    interval: 86400
    health-check:
      enable: true
      url: "https://i.ytimg.com/generate_204"
      interval: 3600
    filter: "🇬🇧|英国" #筛选包含关键字的节点
    #filter: "^(?!.*?海外).*(香港|台湾|日本|新加坡|美国)" #筛选包含关键字及排队包含“海外”的节点
    #filter: "🇬🇧|英国|香港|台湾|日本|新加坡|狮城|美国" 
# proxies，自建节点⬇️⬇️
proxies:
#- {name: type: ss, server: 111.9.146.195, port: '52173', cipher: chacha20-ietf-poly1305, password: juhwygalmcnbvsenuakypz, udp: true}

#proxy-groups，策略组⬇️⬇️
proxy-groups:
  - {name: Select, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/Static.png', type: select, use: [Sub1]}
  - {name: Google, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/Google_1.png', type: select, proxies: [United States, Taiwan, Hongkong, Singapore, Japan]}
  - {name: Apple, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/Apple_1.png', type: select, proxies: [Taiwan, United States, Hongkong, Singapore, Japan]}
  - {name: Microsoft, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/Microsoft.png', type: select, proxies: [Hongkong, Taiwan, United States, Singapore, Japan]}
  - {name: Global, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/Global_1.png', type: select, proxies: [Japan, Hongkong, Taiwan, United States, Singapore]}
  - {name: PayPal, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/PayPal_2.png', type: select, proxies: [United States, Taiwan]}
  - {name: Final, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/Final_1.png', type: select, proxies: [Select, Hongkong, Taiwan, DIRECT]}
  - {name: Hongkong, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/HK_1.png', type: url-test, filter: '(?i)香港|Hongkong', use: [Sub1], health-check: {enable: true, url: 'https://i.ytimg.com/generate_204', interval: 3600, tolerance: 50}}
  - {name: Taiwan, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/TW.png', type: url-test, filter: '(?i)台湾|Taiwan', use: [Sub1], health-check: {enable: true, url: 'https://i.ytimg.com/generate_204', interval: 3600, tolerance: 50}}
  - {name: Singapore, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/SG.png', type: url-test, filter: '(?i)新加坡|Singapore', use: [Sub1], health-check: {enable: true, url: 'https://i.ytimg.com/generate_204', interval: 3600, tolerance: 50}}
  - {name: Japan, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/JP.png', type: url-test, filter: '(?i)日本|Japan', use: [Sub1], health-check: {enable: true, url: 'https://i.ytimg.com/generate_204', interval: 3600, tolerance: 50}}
  - {name: United States, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/US_1.png', type: url-test, filter: '美|United States|USA', use: [Sub1], health-check: {enable: true, url: 'https://i.ytimg.com/generate_204', interval: 3600, tolerance: 50}}
  - {name: United Kingdom, icon: 'https://raw.githubusercontent.com/yeefaye/QuanX/main/icon/UK_1.png', type: select, use: [Sub2, Sub1], filter: '🇬🇧|UK|英国', health-check: {enable: true, url: 'https://i.ytimg.com/generate_204', hidden: true, interval: 3600, tolerance: 50}}
# rule-providers，远程分流规则（规则集）⬇️⬇️
rule-providers:
  Reject: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/refs/heads/main/Rules/Reject.yaml', path: ./providers/rule/Reject.yaml, interval: 864000}
  China: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/China.yaml', path: ./providers/rule/China.yaml, nterval: 864000}
  Google: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/Googlelite.yaml', path: ./providers/rule/Googlelite.yaml, interval: 864000}
  Apple: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/Apple.yaml', path: ./providers/rule/Apple.yaml, interval: 864000}
  AppleUpdate: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/AppleUpdate.yaml', path: ./providers/rule/AppleUpdate.yaml, interval: 864000}
  Microsoft: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/Microsoft.yaml', path: ./providers/rule/Microsoft.yaml, interval: 864000}
  PayPal: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/PayPal.yaml', path: ./providers/rule/PayPal.yaml, interval: 864000}
  Giffgaff: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/Giffgaff.yaml', path: ./providers/rule/Giffgaff.yaml, interval: 864000}
  Proxy: {type: http, behavior: classical, url: 'https://raw.githubusercontent.com/yeefaye/Clash/main/Rules/Proxylite.yaml', path: ./providers/rule/Proxylite.yaml, interval: 864000}
# ⬇️⬇️rules：规则由上往下，如规则命中，不再往下处理⬇️⬇️
rules:
  #本地/局域网⬇️⬇️
  #- DOMAIN-SUFFIX,ip6-localhost,DIRECT,no-resolve
  #- DOMAIN-SUFFIX,ip6-loopback,DIRECT,no-resolve
  #- DOMAIN-SUFFIX,local,DIRECT,no-resolve
  #- DOMAIN-SUFFIX,localhost,DIRECT,no-resolve
  #- DOMAIN-SUFFIX,lan,DIRECT,no-resolve
  - IP-CIDR,84.54.0.0/22,Select,no-resolve
  #pt/bt⬇️⬇️
  - DOMAIN-SUFFIX,discfan.net,DIRECT
  - DOMAIN-SUFFIX,discfan.xyz,DIRECT
  - DOMAIN-SUFFIX,0ff.cc,DIRECT
  - DOMAIN-SUFFIX,bt0.com,DIRECT
  - DOMAIN-SUFFIX,a4apt.com,DIRECT
  - DOMAIN-SUFFIX,okpt.top,DIRECT
  - DOMAIN-SUFFIX,m-team.cc,DIRECT
  - DOMAIN-SUFFIX,m-team.io,DIRECT
  - DOMAIN-SUFFIX,halomt.com,DIRECT
  - DOMAIN-SUFFIX,manfuz.co,DIRECT
  - DOMAIN-KEYWORD,announce.php,DIRECT
  #其它⬇️⬇️
  - DOMAIN-SUFFIX,yifai999.shop,DIRECT
  - DOMAIN-SUFFIX,livednow.com,Select
  - DOMAIN-SUFFIX,cnbeta.com.tw,Select
  - DOMAIN-SUFFIX,huaweicloud.com,DIRECT
  - DOMAIN,component-ota-in.allawnos.com,REJECT
  - PROCESS-NAME,org.localsend.localsend_app,DIRECT
  - PROCESS-NAME,localsend,DIRECT
  #NAS
  - DOMAIN-SUFFIX,myqnapcloud.io,Hongkong
  - DOMAIN-SUFFIX,myqnapcloud.com,Hongkong
  - DOMAIN-KEYWORD,myqnapcloud,Hongkong
  - DOMAIN-SUFFIX,qnap.com,Hongkong
  - DOMAIN-SUFFIX,qlink.to,Hongkong
  - SRC-IP-CIDR,192.168.55.113/32,DIRECT,no-resolve  #指定内设备ip直连
  # iptv⬇️⬇️
  - DOMAIN-SUFFIX,kktv.com.tw,Taiwan
  - DOMAIN-SUFFIX,kktv.me,Taiwan
  - DOMAIN-SUFFIX,kk.stream,Taiwan
  - DOMAIN-SUFFIX,chocotv.com.tw,Taiwan
  - DOMAIN-SUFFIX,line-cdn.net,Taiwan
  - DOMAIN-SUFFIX,line-scdn.net,Taiwan
  - DOMAIN-SUFFIX,linetv.tw,Taiwan
  - DOMAIN-SUFFIX,litv.tv,Taiwan
  - DOMAIN-SUFFIX,LiTV.tv,Taiwan
  - DOMAIN-SUFFIX,chinet.net,Taiwan
  - DOMAIN-SUFFIX,hinet.net,Taiwan
  - DOMAIN-SUFFIX,4gtv.tv,Taiwan
  - DOMAIN-SUFFIX,ntdofifreepc.akamaized.net,Taiwan
  - DOMAIN-SUFFIX,ntdofifreepocpc.akamaized.net,Taiwan
  - DOMAIN-SUFFIX,ntdofifreevcpc.akamaized.net,Taiwan
  - DOMAIN-KEYWORD,hamivideo,Taiwan
  - DOMAIN-KEYWORD,hinet,Taiwan
  - DOMAIN-KEYWORD,4gtv,Taiwan
  - DOMAIN-SUFFIX,astro.com.my,Singapore
  # 策略分流RULE-SET⬇️⬇️
  - RULE-SET,AppleUpdate,REJECT
  - RULE-SET,Reject,REJECT
  - RULE-SET,Google,Google
  - RULE-SET,Apple,Apple
  - RULE-SET,Microsoft,Microsoft
  - RULE-SET,Giffgaff,United Kingdom
  - RULE-SET,PayPal,PayPal
  - RULE-SET,Proxy,Global
  - RULE-SET,China,DIRECT
  # GEOIP，如你不希望进行DNS解析，在GEOIP规则的最后加上no-resolve.
  - GEOIP,CN,DIRECT,no-resolve
  # 必须，MATCH，前面的规则都没有命中，走MATCH，放在最后。
  - MATCH,Final
```

## 鸣谢

  [@jamesdailylife](https://jamesdaily.life/rule-proxy-provider)

  [@KOP-XIAO](https://github.com/KOP-XIAO)

  [@DivineEngine](https://github.com/DivineEngine/Profiles/tree/master)

  [@ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master)
  
 [@Semporia](https://github.com/Semporia)

  [@helmiau](https://github.com/helmiau/clashrules)

  [@Loyalsoldier](https://github.com/Loyalsoldier/clash-rules)

  [@ricky9w](https://gist.github.com/ricky9w/31fffc1b6eadadba2603f323dc92bebf)

  [@Dreamacro](https://github.com/Dreamacro/clash/wiki/configuration#proxy-groups)

  [@blackmatrix7](https://github.com/blackmatrix7/ios_rule_script)

