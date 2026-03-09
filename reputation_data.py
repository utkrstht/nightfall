ASN_REPUTATION = {
    "15169": 5,   # Google
    "16509": 20,  # Amazon/AWS
    "13335": 15,  # Cloudflare
    "60068": 95,  # Datacamp (VPN)
    "212238": 98, # Datapacket (VPN)
    "202425": 85, # IP Volume (VPN)
    "16276": 45,  # OVH
    "24940": 45,  # Hetzner
    "396982": 99, # Mullvad
    "40021": 95,  # M247
    "212239": 98, # Datapacket
    "20473": 30,  # Vultr
    "14061": 30,  # DigitalOcean
    "20857": 90,  # Windscribe
    "30083": 95,  # Surfshark
    "13678": 95,  # ExpressVPN (Kentic)
    "20940": 5,   # Akamai
    "15133": 5,   # Verizon
    "7018": 5,    # AT&T
    "7922": 5,    # Comcast/Xfinity
    "3356": 10,   # Level3
    "174": 15,    # Cogent
    "2914": 5,    # NTT Communications
    "6453": 5,    # Tata Communications
    "1239": 5,    # Sprint
    "3215": 5,    # Orange
    "3320": 5,    # Deutsche Telekom
    "1273": 5,    # Vodafone
    "2856": 5,    # BT
    "5508": 15,   # Akamai
    "20448": 95,  # G-Core Labs
    "20001": 40,  # Cloudflare Warp
    "45102": 95,  # Alibaba
    "8075": 10,   # Microsoft
    "12008": 5,   # Neustar
    "19318": 40,  # QuadraNet
    "46606": 90,  # Unified Layer (EIG)
    "46562": 90,  # Performive
    "35916": 95,  # Multacom
    "53667": 95,  # FranTech (BuyVM)
    "210644": 95, # Aeza
    "54203": 95,  # Scaleway
    "36351": 35,  # Softlayer
    "13238": 5,   # Yandex
    "4134": 5,    # China Telecom
    "4837": 5,    # China Unicom
    "9808": 5,    # China Mobile
    "15003": 95,  # HideMyAss
    "2516": 5,    # KDDI
    "2497": 5,    # IIJ
    "4766": 5,    # Korea Telecom
    "2500": 5,    # SK Broadband
    "9318": 5,    # Hanaro
    "4713": 5,    # NTT Japan
    "12322": 5,   # Free SAS
    "3269": 5,    # Telecom Italia
    "6830": 5,    # Liberty Global
    "2859": 5,    # Telenet
    "2119": 5,    # Telenor
    "3301": 5,    # TeliaSonera
    "1257": 5,    # Tele2
    "3352": 5,    # Telefonica Spain
    "15557": 5,   # SFR
    "20115": 5,   # Charter
    "11427": 5,   # Time Warner
    "5650": 5,    # Frontier
    "852": 5,     # TELUS
    "812": 5,     # Rogers
    "577": 5,     # Bell Canada
    "1221": 5,    # Telstra
    "4808": 5,    # CNCGroup
    "55836": 99,  # Reliance Jio
    "45609": 10,  # Bharti Airtel
    "9829": 5,    # BSNL
    "56106": 98,  # NordVPN Servers
    "50892": 95,  # Mullvad Servers
    "209588": 99, # 302.network (Proxies)
    "210558": 99, # FineProxy
    "34305": 99,  # ZenMate
    "50498": 98,  # ProtonVPN
    "50304": 95,  # Windscribe
    "200651": 95, # Le-VPN
    "206264": 98, # Surfshark B.V.
    "51852": 99   # Private Internet Access
}

def get_asn_trust_score(asn: int, is_vpn: bool, is_proxy: bool) -> int:
    asn_key = str(asn)
    risk_score = ASN_REPUTATION.get(asn_key, 0)
    
    if is_vpn:
        risk_score = max(risk_score, 90)
    elif is_proxy:
        risk_score = max(risk_score, 40)
        
    trust_score = 100 - risk_score
    
    return max(1, min(99, trust_score))
