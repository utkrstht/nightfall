# nightfall
an IP whois service (ipv4 only)

## how to use
i don't have it deployed right now, i'll probably have it running soon

## what does it do
it's an IP whois service, it's very basic for now.

we crawl the whois registry, and about every 11-ish days we get a fresh dataset of IP info.

unless you fetch an IP that is not in our database, you'll get the one in the database (max 11 days old data)

## what information do i get
you'll get the following information in the following format:
```
{
  "ip": "8.8.8.8",
  "success": true,
  "type": "IPv4",
  "prefix": "8.8.8.0/24",
  "continent": "North America",
  "continent_code": "NA",
  "country": null,
  "country_code": "US",
  "region": null,
  "city": null,
  "latitude": null,
  "longitude": null,
  "flag": {
    "img": "https://cdn.ipwhois.io/flags/us.svg",
    "emoji": "🇺🇸",
    "emoji_unicode": "U+1F1FA U+1F1F8"
  },
  "connection": {
    "asn": 15169,
    "org": "GOOGLE - Google LLC, US",
    "isp": "GOOGLE - Google LLC, US",
    "type": "hosting",
    "domain": "dns.google"
  },
  "timezone": {
    "id": "America/New_York",
    "abbr": "EST",
    "is_dst": false,
    "offset": -18000,
    "utc": "-0500"
  },
  "last_updated": "2026-03-06T12:15:02.401252+00:00",
  "postal": null,
  "calling_code": "1",
  "capital": "Washington D.C.",
  "borders": "CA,MX"
}
```
the information that is null, currently isn't supported (i'm working on it!)