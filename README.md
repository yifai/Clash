### 分流规则收集自网络，整理修改，自用Clash分流规则集合

 rule-providers：俗称规则集合，通过它，可以引用不同类型的在线规则集 （URL），clash 就能自动根据访问目标是否在规则集中，然后匹配到对应的规则，从而选择代理/节点或者本地网络进行访问。简单地说，rule-provider 能让在线的规则集，下载到本地供我们使用，配合rules/RULE-SET使用。

 proxy-providers：俗称代理集合，通过它，可以提取指定 Clash订阅链接或者本地配置文件中的proxies字段中的所有内容。简单地说，proxy-providers 帮助我们提取订阅链接或者配置文件中所包含的节点信息，到当前配置文件中供我们使用（不使用机场/原来的分流规则）

##### 分流规则（策略）看个人使用习惯，适合增加/减少，无特别要求，使用GFW列表规则走代理，其它直连即可。
### 下方示例配置适用于使用各个clash内核的客户端，包括苹果的Stash。
#### 在proxy-providers下的url填入clash订阅即可使用，规则集(rule-providers)及proxy-groups(策略或代理组)可按个人需求增减
```mixed-port: 7890      # 本地混合代理(http和socks5合并）端口
mode: rule            # clash工作模式（rule/global/direct,meta暂不支持script）
ipv6: false           # ip6开关，当为false时，停止解析hostanmes为ip6地址
log-level: info       # 日志等级 （info/warning/error/debug/silent）
allow-lan: false      # 是否允许局域网链接(false/true)
unified-delay: false  # 統一延遲
tcp-concurrent: true
external-controller: 127.0.0.1:9236   # 外部控制器地址

clash-for-android:
  append-system-dns: false

profile:
  store-selected: true
  store-fake-ip: true
  tracing: true
  
hosts:
  mtalk.google.com: 108.177.97.188
  
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
  
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  listen: 127.0.0.1:1853
  
  default-nameserver:  #默认dns, 用于解析 DNS 器 的域名
    - "223.5.5.5"
    - "119.29.29.29"
    - "8.8.8.8"
    
  nameserver:  #默认的域名解析器，如不配置 fallback/proxy-server-nameserver , 则所有域名都由 nameserver 解析
    - "https://doh.pub/dns-query"
    - "https://dns.alidns.com/dns-query"
  
  #proxy-server-nameserver:  #代理域名解析器，仅用于解析代理的域名
    #- "https://doh.pub/dns-query"
    #- "https://1.0.0.1/dns-query"
    
  fallback:  #后备域名解析器，一般情况下使用境外 DNS, 保证结果可信，配置 fallback后默认启用 fallback-filter,geoip-code为 cn
    - "tls://8.8.4.4:853"
    - "https://dns.cloudflare.com/dns-query"
    - "https://1.1.1.1/dns-query"
    
   # 在以下列表的域名将不会被解析为 fake ip，这些域名相关的解析请求将会返回它们真实的 IP 地址
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.example"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - time.*.com
    - time.*.gov
    - time.*.edu.cn
    - time.*.apple.com
    - time1.*.com
    - time2.*.com
    - time3.*.com
    - time4.*.com
    - time5.*.com
    - time6.*.com
    - time7.*.com
    - ntp.*.com
    - ntp1.*.com
    - ntp2.*.com
    - ntp3.*.com
    - ntp4.*.com
    - ntp5.*.com
    - ntp6.*.com
    - ntp7.*.com
    - "*.time.edu.cn"
    - "*.ntp.org.cn"
    - +.pool.ntp.org
    - time1.cloud.tencent.com
    - stun.*.*
    - stun.*.*.*
    - swscan.apple.com
    - mesu.apple.com
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - musicapi.taihe.com
    - music.taihe.com
    - songsearch.kugou.com
    - trackercdn.kugou.com
    - "*.kuwo.cn"
    - api-jooxtt.sanook.com
    - api.joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - localhost.ptlogin2.qq.com
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - +.wotgame.cn
    - +.wggames.cn
    - +.wowsgame.cn
    - +.wargaming.net
    - "*.*.*.srv.nintendo.net"
    - "*.*.stun.playstation.net"
    - "+.playstation.com"
    - "+.playstation.net"
    - "+.xboxlive.com"
    - "+.microsoft.com" 
    - xbox.*.*.microsoft.com
    - "*.*.xboxlive.com"
    - "*.ipv6.microsoft.com"
    - teredo.*.*.*
    - teredo.*.*
    - speedtest.cros.wr.pvp.net
    - +.jjvip8.com
    - www.douyu.com
    - activityapi.huya.com
    - activityapi.huya.com.w.cdngslb.com
    - www.bilibili.com
    - api.bilibili.com
    - a.w.bilicdn1.com
    
  fallback-filter:     #后备域名解析器筛选，满足条件的将使用 fallback结果或只使用 fallback解析
    geoip: true        #为真时，不匹配为geoip规则的使用fallback返回结果
    geoip-code: CN     #geoip匹配区域设定
    ipcidr:            #列表中的ip使用fallback返回解析结果
      - 240.0.0.0/4
      - 0.0.0.0/32
      - 127.0.0.1/32
    domain:            #列表中的域名使用fallback返回解析结果
      - +.facebook.com
      - +.twitter.com
      - +.google.com
      - +.googleapis.com
      
proxy-providers:
  Sub:
    type: http
    path: ./providers/proxy/Sub.yaml
    url: "填写clash订阅"
    interval: 86400
    health-check:
      enable: true
      url: "https://i.ytimg.com/generate_204"
      #url: "http://cp.cloudflare.com/generate_204"
      interval: 1200
    filter: "(?i)United States|美国|Hong kong|香港|taiwan|台湾|Singapore|新加坡|Japan|日本"  #筛选包含关键字的节点
    #filter: "^(?!.*?海外).*(香港|台湾|日本|新加坡|美国)" #筛选包含关键字及排队包含“海外”的节点
    #exclude-filter: "海外"  #排队包含“海外”的节点
    
#proxies自建
proxies:
  #- {name: type: ss, server: 111.9.146.195, port: "52173", cipher: chacha20-ietf-poly1305, password: juhwygalmcnbvsenuakypz, udp: true}
  
#proxy-groups：策略组
proxy-groups:

  - {name: 🚀select, type: select, use: [Sub], proxies: [DIRECT]}
  
  - {name: 📢Google, type: select, proxies: [🚀select, 🇭🇰HongKong, 🇹🇼Taiwan, 🇺🇸American, 🇸🇬Singapore, 🇯🇵Japan]}
  
  - {name: 🍎Apple, type: select, proxies: [DIRECT, 🇭🇰HongKong, 🇹🇼Taiwan, 🇺🇸American, 🇸🇬Singapore, 🇯🇵Japan]}
  
  - {name: Ⓜ️MicroSoft, type: select, proxies: [🚀select, DIRECT, 🇭🇰HongKong, 🇹🇼Taiwan, 🇺🇸American, 🇸🇬Singapore, 🇯🇵Japan]}
  
  - {name: 🌎Global, type: select, proxies: [🚀select, 🇭🇰HongKong, 🇹🇼Taiwan, 🇺🇸American, 🇸🇬Singapore, 🇯🇵Japan]}
  
  - {name: 💸PayPal, type: select, proxies: [🇺🇸American, 🇹🇼Taiwan]}
  
  - {name: 🏁Final, type: select, proxies: [🚀select, DIRECT]}
  
  - {name: 🇭🇰HongKong, type: url-test, filter: "(?i)香港|Hongkong|hong kong", use: [Sub], health-check: {enable: true, url: "https://i.ytimg.com/generate_204", interval: 1200, tolerance: 50}}
  
  - {name: 🇹🇼Taiwan, type: url-test, filter: "(?i)台湾|Taiwan", use: [Sub], health-check: {enable: true, url: "https://i.ytimg.com/generate_204", interval: 1200, tolerance: 50}}
  
  - {name: 🇸🇬Singapore, type: url-test, filter: "(?i)新加坡|SG|Singapore", use: [Sub], health-check: {enable: true, url: "https://i.ytimg.com/generate_204", interval: 1200, tolerance: 50}}
  
  - {name: 🇯🇵Japan, type: url-test, filter: "(?i)日本|JP|Japan", use: [Sub], health-check: {enable: true, url: "https://i.ytimg.com/generate_204", interval: 1200, tolerance: 50}}
  
  - {name: 🇺🇸American, type: url-test, filter: "🇺🇸|United States|美国", use: [Sub], health-check: {enable: true, url: "https://i.ytimg.com/generate_204", interval: 1200, tolerance: 50}}
  
#rule-providers：远程分流规则
rule-providers:

  Reject: {type: http, behavior: classical, url: "https://raw.githubusercontent.com/yifai/Clash/main/Reject.yaml", path: ./providers/rule/Reject.yaml, interval: 864000}
  
  China: {type: http,behavior: classical, url: "https://raw.githubusercontent.com/yifai/Clash/main/China.yaml", path: ./providers/rule/China.yaml, nterval: 864000}
  
  Google: {type: http, behavior: classical, url: "https://raw.githubusercontent.com/yifai/Clash/main/Google.yaml", path: ./providers/rule/Google.yaml, interval: 864000}
    
  Apple: {type: http, behavior: classical, url: "https://raw.githubusercontent.com/yifai/Clash/main/Apple.yaml", path: ./providers/rule/Apple.yaml, interval: 864000}
    
  Microsoft: {type: http, behavior: classical, url: "https://raw.githubusercontent.com/yifai/Clash/main/Microsoft.yaml", path: ./providers/rule/Microsoft.yaml, interval: 864000}
  
  PayPal: {type: http, behavior: classical, url: "https://raw.githubusercontent.com/yifai/Clash/main/PayPal.yaml", path: ./providers/rule/PayPal.yaml, interval: 864000}
    
  Proxy: {type: http, behavior: classical, url: "https://raw.githubusercontent.com/yifai/Clash/main/Proxylite.yaml", path: ./providers/rule/Proxy.yaml, interval: 864000}
  
# rules规则由上往下遍历，如上面规则已经命中，则不再往下处理
rules:
  #本地/局域网
  - DOMAIN-SUFFIX,ip6-localhost,DIRECT,no-resolve
  - DOMAIN-SUFFIX,ip6-loopback,DIRECT,no-resolve
  - DOMAIN-SUFFIX,local,DIRECT,no-resolve
  - DOMAIN-SUFFIX,localhost,DIRECT,no-resolve
  - DOMAIN-SUFFIX,lan,DIRECT,no-resolve
  
  #其它
  - PROCESS-NAME,BitComet,DIRECT
  - PROCESS-NAME,qbittorrent,DIRECT
  - DOMAIN-SUFFIX,yowindow.ru,DIRECT
  - DOMAIN-SUFFIX,yowindow.com,DIRECT
  
  # 策略分流RULE-SET
  - RULE-SET,Reject,REJECT
  - RULE-SET,Google,📢Google
  - RULE-SET,Apple,🍎Apple
  - RULE-SET,Microsoft,Ⓜ️MicroSoft
  - RULE-SET,PayPal,💸PayPal
  - RULE-SET,Proxy,🌎Global
  - RULE-SET,China,DIRECT
  
  # GEOIP ，如你不希望进行 DNS 解析，可在 GEOIP 规则的最后加上 ,no-resolve，如 GEOIP,CN,DIRECT,no-resolve。
  #GEOIPCN，ChinaIP二选一
  - GEOIP,CN,DIRECT,no-resolve
  
  # 必须，MATCH，前面的规则都没有命中，走MATCH，放在最后。
  - MATCH,🏁Final
```

## 鸣谢

  [@jamesdailylife](https://jamesdaily.life/rule-proxy-provider)

  [@DivineEngine](https://github.com/DivineEngine/Profiles/tree/master)

  [@ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master)
  
 [@Semporia](https://github.com/Semporia)

  [@helmiau](https://github.com/helmiau/clashrules)

  [@Loyalsoldier](https://github.com/Loyalsoldier/clash-rules)

  [@ricky9w](https://gist.github.com/ricky9w/31fffc1b6eadadba2603f323dc92bebf)

  [@Dreamacro](https://github.com/Dreamacro/clash/wiki/configuration#proxy-groups)
  
  [@justdoiting](https://github.com/justdoiting/clash-rule)

  [@blackmatrix7](https://github.com/blackmatrix7/ios_rule_script)
