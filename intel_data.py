VPN_KEYWORDS = [
    "nordvpn", "expressvpn", "surfshark", "protonvpn", "mullvad", "cyberghost", "tunnelbear", "ivpn", "vpn-layer", 
    "windscribe", "ipvanish", "purevpn", "hidemyass", "torguard", "privateinternetaccess", "vyprvpn", "strongvpn",
    "atlas vpn", "hotspot shield", "zenmate", "speedify", "trusted-proxy", "smart-proxy", "snail-proxy", "hola vpn",
    "privatevpn", "airvpn", "vpnunlimited", "ghostpath", "le-vpn", "trust.zone", "vpn.ac", "ovpn.com", "marlinvpn",
    "vpnhub", "vpnsafety", "vpnsecure", "vpnshazam", "vpntunnel", "wildfire vpn", "x-vpn", "yoga vpn", "zaborona",
    "z-vpn", "anonine", "astrill", "avira phantom", "bitdefender vpn", "bullguard vpn", "cactusvpn", "fastvpn",
    "f-secure freedome", "goose vpn", "hide.me", "iamanon", "ipredator", "ivacy", "kaspersky vpn", "keepsolid",
    "mcafee safe connect", "namesilo vpn", "norton secure vpn", "ovpn", "perfect privacy", "privatevpns",
    "slickvpn", "smartvps", "surfeasy", "tor-guard", "vpn-gate", "vpngate", "vpnht", "vpnstaticip", "vpzone",
    "webroot wifi security", "wi-top", "zenvpn", "zerovpn", "v2ray", "shadowsocks", "wireguard", "openvpn",
    "softether", "ikev2", "l2tp", "pptp", "sstp", "ipsec", "anonymizer", "proxy-service", "unblocker", "bypass-geofence"
]

HOSTING_KEYWORDS = [
    "amazon", "aws", "google cloud", "gcp", "microsoft azure", "azure", "digitalocean", "vultr", "linode", "ovh", 
    "hetzner", "scaleway", "choopa", "leaseweb", "contabo", "alibaba", "oracle cloud", "tencent cloud", "fastly", 
    "akamai", "cloudflare", "datacenter", "hosting", "datapacket", "datacamp", "cogent", "worldstream", "m247", 
    "psychz", "quadranet", "liquidweb", "iomart", "interxion", "equinix", "teraco", "global switch", "softlayer", 
    "ibm cloud", "stc cloud", "zscaler", "forcepoint", "netskope", "server", "colo", "compute", "node", "dedicated", 
    "vps", "dedicated-server", "cloud-computing", "iaas", "paas", "virtuozzo", "kvm", "xen", "vmware", "hyper-v",
    "bluehost", "hostgator", "dreamhost", "siteground", "a2hosting", "inmotion hosting", "wp engine", "kinsta", 
    "pantheon", "cloudways", "digital ocean", "ramnode", "buyvm", "lowendbox", "greenhouse", "switch.ch", "ovhcloud",
    "hivelocity", "reliablesite", "fdcservers", "wholesaleinternet", "joesdatacenter", "datacentre", "telehouse",
    "tier3", "tier4", "cogentco", "telia", "tata communications", "pccw global", "ntt communications", "zayo",
    "gtt", "lumen", "centurylink", "frontier", "windstream", "atlantic.net", "vultr.com", "linode.com"
]

CRAWLER_KEYWORDS = [
    "googlebot", "bingbot", "duckduckbot", "yandexbot", "baiduspider", "facebookexternalhit", "twitterbot", 
    "linkedinbot", "slackbot", "discordbot", "applebot", "crawler", "spider", "bot", "scrapy", "python-requests", 
    "aiohttp", "guzzle", "headless", "puppeteer", "selenium", "playwright", "semrushbot", "ahrefsbot", "dotbot", 
    "mojolicious", "mj12bot", "adsbot", "mediapartners-google", "apis-google", "bingpreview", "baiduspider-render",
    "sogou", "exabot", "rogue-bot", "blackwidow", "webcrawler", "webcopy", "httrack", "wget", "curl", "libwww-perl",
    "python-urllib", "php-curl", "jakarta commons-httpclient", "java-http-client", "ruby-http-client", "go-http-client",
    "node-fetch", "axios", "superagent", "postman", "insomnia", "thunder client", "rest-client", "w3c_validator",
    "jigsaw", "pingdom", "uptimerobot", "statuscake", "freshping", "site24x7", "gtmetrix", "lighthouse", "pagespeed",
    "monit", "nagios", "zabbix", "prometheus", "grafana", "netdata", "datadog", "newrelic", "appdynamics", "dynatrace"
]

PROXY_NETWORKS = [
    "oxylabs", "brightdata", "smartproxy", "iproyal", "soax", "luminati", "packetstream", "stormproxies", "geosurf", 
    "netnut", "proxycheap", "proxyscrape", "webshare", "proxy-seller", "proxy-io", "proxy-rack", "buyproxies", 
    "highproxies", "sslprivateproxy", "myprivateproxy", "instantproxies", "proxy-hub", "limetray", "proxy-solutions",
    "residential-proxy", "mobile-proxy", "isp-proxy", "socks5", "socks4", "http-proxy", "https-proxy", "anonymizer",
    "webproxy", "hide-my-ip", "hide-my-ass", "proxy-site", "kproxy", "proxysite"
]

MOBILE_KEYWORDS = [
    "lte", "4g", "5g", "mobile", "cellular", "wireless", "carrier", "gateway", "wap", "apn", "mobi", "sprint", 
    "t-mobile", "vodafone", "verizon wireless", "at&t mobility", "ee limited", "o2 mobile", "telefonica mobile",
    "starlink", "gsm", "cdma", "umts", "hspa", "edge", "gprs", "cell-site", "tower", "cell-tower", "radio-access",
    "ran", "c-ran", "v-ran", "packet-core", "mme", "sgw", "pgw", "upf", "amf", "smf", "ausf", "udm", "nrf", "nssf"
]

BOGON_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "169.254.0.0/16", "127.0.0.1/32",
    "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7"
]

RDNS_PROXY_INDICATORS = [
    "proxy", "vpn", "vps", "hosting", "server", "datacenter", "colo", "cloud", "dedicated", "compute", "node", 
    "exit", "relay", "tor", "unn-", "hosted-by", "ptr", "dynamic", "static", "cust", "dialup", "pool", "bras", 
    "dsl", "cable", "fiber", "ftth", "fttp", "fttc", "nodes", "bridges", "gateways", "outbound", "inbound", 
    "traffic", "filter", "scrubbing", "anti-ddos", "cdn", "edge-node", "cache", "pop"
]
