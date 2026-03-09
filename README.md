# nightfall
an IP whois service 

(ipv6 is supported as well!)

> [!NOTE]
> alot of the time, instead of triggering `is_vpn`, <br>
> it'll trigger `is_proxy`, i'll fix this later lol

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
endpoints: /v1/ip/<ip>, 
           /v1/bulk?ips=<ip1>,<ip2> (500 max)
           /v1/asn/<asn>

quick rundown on some important fields:
- is_bogon: means ip provided is a loopback/localhost ip
- is_discrepancy: means the ip's country didn't match user's language headers
- latitude/longitude: these are the city latitude and longitudes lol, i'll make it more accurate later i guess.

you'll get the following information in the following format
(null information means it's not been processed yet):

/v1/ip
```
{
  "ip": "8.8.8.8",
  "success": true,
  "type": "IPv4",
  "prefix": "8.8.8.0/24",
  "continent": "North America",
  "continent_code": "NA",
  "country": "United States",
  "country_code": "US",
  "region": "California",
  "city": "Mountain View",
  "latitude": 37.751,
  "longitude": -97.822,
  "postal": "94043",
  "calling_code": "+1",
  "capital": "Washington, D.C.",
  "borders": "CAN,MEX",
  "flag": {
    "img": "https://cdn.ipwhois.io/flags/us.svg",
    "emoji": "🇺🇸",
    "emoji_unicode": "U+1F1FA U+1F1F8"
  },
  "connection": {
    "asn": 15169,
    "org": "GOOGLE - Google LLC, US",
    "isp": "Google",
    "type": "hosting",
    "domain": "dns.google",
    "abuse_email": null
  },
  "security": {
    "is_vpn": false,
    "is_tor": false,
    "is_crawler": false,
    "is_proxy": true,
    "is_mobile": false,
    "is_hosting": false,
    "is_bogon": false,
    "is_discrepancy": false,
    "threat_score": 0,
    "threat_level": "medium",
    "abuse_email": null,
    "fingerprint": null
  },
  "timezone": {
    "id": "America/New_York",
    "abbr": "EDT",
    "is_dst": true,
    "offset": -14400,
    "utc": "-0400"
  },
  "last_updated": "2026-03-08T12:52:10.182728+00:00"
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
