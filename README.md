# nightfall
an IP whois service 

(ipv6 is supported as well!)

## how to use
i don't have it deployed right now, i'll probably have it running soon

## vpn/proxy/tor/crawler detection
the detection is decently accurate, ~75% accurate (i pulled this number out of my ass lol)

if you're using this service to determine if a user is using a VPN or not, and have the browser <br> headers of the user (e.g from the user using your services/website or something)

you can pass the `User-Agent` and the `Accept-Language` headers to our API headers as <br>`X-Forwarded-User-Agent` and `X-Forwarded-Accept-Language` respectively for more accurate VPN <br> detection (see below for a node example)

example (nodejs):
```js
const axios = require('axios');

app.get('/check-user', async (req, res) => {
    const userIp = req.ip; 
    
    const response = await axios.get(`apiurl`, {
        headers: {
            'X-Forwarded-User-Agent': req.headers['user-agent'],
            'X-Forwarded-Accept-Language': req.headers['accept-language']
        }
    });

    res.json(response.data);
});
```

## what does it do
it's an IP whois service, read below on what information you get.

we crawl the whois registry, and about every 11-ish days we get a fresh dataset of IP info.

unless you fetch an IP that is not in our database, you'll get the one in the database (max 11 days old data)

## what information do i get
endpoints: - /v1/ip/<ip>, <br>
           - /v1/bulk?ips=<ip1>,<ip2> (500 max) <br>
           - /v1/asn/<asn> <br>

quick rundown on some important fields:
- is_bogon: means ip provided is a loopback/localhost ip
- is_discrepancy: means the ip's country didn't match user's language headers
- latitude/longitude: these are the city latitude and longitudes lol, i'll make it more accurate later i guess.
- threat_score: how likely is it to be a VPN (the logic is screwed up and all so like ignore this), higher = more vpn (this does NOT mean malicious activity)

you'll get the following information in the following format
(null information means it's not been processed yet):

/v1/ip
```
{
  "ip": "205.147.17.22",
  "success": true,
  "type": "IPv4",
  "prefix": "205.147.17.0/24",
  "continent": "Europe",
  "continent_code": "EU",
  "country": "Norway",
  "country_code": "NO",
  "region": null,
  "city": "Oslo",
  "latitude": 59.9056,
  "longitude": 10.7494,
  "postal": null,
  "calling_code": "+47",
  "capital": "Oslo",
  "borders": "FIN,SWE,RUS",
  "flag": {
    "img": "https://cdn.ipwhois.io/flags/no.svg",
    "emoji": "🇳🇴",
    "emoji_unicode": "U+1F1F3 U+1F1F4"
  },
  "connection": {
    "asn": 208172,
    "org": "PV-HOSTED, CH",
    "isp": "PV-HOSTED, CH",
    "type": "residential",
    "domain": null,
    "abuse_email": null
  },
  "security": {
    "is_vpn": true,
    "is_tor": false,
    "is_crawler": false,
    "is_mobile": false,
    "is_bogon": false,
    "is_discrepancy": true,
    "threat_score": 100,
    "threat_level": "high",
    "abuse_email": "abuse.importer974@passmail.net",
    "fingerprint": null
  },
  "timezone": {
    "id": "Europe/Oslo",
    "abbr": "CET",
    "is_dst": false,
    "offset": 3600,
    "utc": "+0100"
  },
  "last_updated": "2026-03-10T11:49:05.357276+00:00"
}
```
/v1/bulk?ips=8.8.8.8,1.1.1.1
```
[
  {
    "ip": "8.8.8.8",
    ....
  },
  {
    "ip": "1.1.1.1",
    ....
  }
]
```
/v1/asn/<asn>
```
{
  "asn": "AS15169",
  "organization": "Google LLC",
  "prefixes": [
    "108.1.108.0/24",
    "176.2.132.0/24",
    "188.132.165.0/24",
    "195.186.228.0/24",
    "2001:4860::/32",
    "35.40.63.0/18",
    "36.100.152.0/22",
    "40.201.52.0/23",
    "8.8.8.0/24"
  ],
  "count": 9
}
```
