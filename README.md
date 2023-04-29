个人收集自用Clash分流规则集合（rule-provider）

rule-provider：俗称规则集合，通过它，可以引用不同类型的在线规则集 （URL），clash 就能自动根据访问目标是否在规则集中，然后匹配到对应的规则，从而选择代理/节点或者本地网络进行访问。简单地说，rule-provider 能让在线的规则集，下载到本地供我们使用，配合rules/RULE-SET使用。

proxy-provider：俗称代理集合，通过它，可以提取指定 Clash订阅链接或者本地配置文件中的proxies字段中的所有内容。简单地说，proxy-provider 帮助我们提取订阅链接或者配置文件中所包含的节点信息，到当前配置文件中供我们使用（不使用机场/原来的分流规则）
# Extra目录下为细分的各项分流规则，无特别要求，使用clash目录下的分流规则即可，注意：GEOIP,CN和chinaIP二选一。
# 特别注意：rule-provider、proxy-provider 适用于 Clash Premium 内核的规则集（RULE-SET），同时适用于所有使用 Clash Premium 内核的 Clash 图形用户界面（GUI）客户端。

# 配置规则参考文档： https://github.com/Dreamacro/clash/wiki/configuration

# 按自己的需求选择规则集合，例如，你想国内直连，其它的代理，就可以选择China.yaml这个规则集（rule-provider），再加上GEOIP,CN，最后MATCH代理即可（即China.yaml和GEOIP,CN之外的规则全部代理）；在China.yaml和GEOIP,CN之外，也可以加上特定的规则集，比如Paypal单独选择代理节点，分流（rule）添加于MATCH前面

# 参考/引用资源（不分先后顺序），感谢各位大佬的无私分享。

  https://www.jamesdailylife.com/rule-proxy-provider

  https://github.com/Semporia

  https://github.com/helmiau/clashrules

  https://github.com/Loyalsoldier/clash-rules

  https://gist.github.com/ricky9w/31fffc1b6eadadba2603f323dc92bebf

  https://github.com/Dreamacro/clash/wiki/configuration#proxy-groups
  
  https://github.com/justdoiting/clash-rule

  https://github.com/blackmatrix7/ios_rule_script
