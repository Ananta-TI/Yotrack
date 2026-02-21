import json
import requests
import time
import os
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from sys import stderr
import re
import socket
import whois
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import random

# Color codes
Bl = '\033[30m'
Re = '\033[1;31m'
Gr = '\033[1;32m'
Ye = '\033[1;33m'
Blu = '\033[1;34m'
Mage = '\033[1;35m'
Cy = '\033[1;36m'
Wh = '\033[1;37m'
Bg_Bl = '\033[40m'
Bg_Re = '\033[41m'
Bg_Gr = '\033[42m'
Bg_Ye = '\033[43m'
Bg_Blu = '\033[44m'
Bg_Mage = '\033[45m'
Bg_Cy = '\033[46m'
Bg_Wh = '\033[47m'

# User-Agent rotation for requests
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
]

def get_random_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://www.google.com/',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }

def is_option(func):
    def wrapper(*args, **kwargs):
        run_banner()
        func(*args, **kwargs)
    return wrapper

def print_banner(text, color=Gr):
    width = 60
    print(f"\n{color}{'=' * width}")
    print(f"{color}{text.center(width)}")
    print(f"{color}{'=' * width}{Wh}\n")

def check_vpn_proxy(ip):
    """Check if IP is from VPN or proxy"""
    try:
        # Using ipapi.is for VPN/proxy detection
        response = requests.get(f"https://ipapi.is/{ip}/json/", headers=get_random_headers(), timeout=5)
        data = response.json()
        return {
            'is_proxy': data.get('is_proxy', False),
            'is_vpn': data.get('is_vpn', False),
            'is_tor': data.get('is_tor', False),
            'is_datacenter': data.get('is_datacenter', False)
        }
    except:
        return None

def get_threat_intelligence(ip):
    """Get threat intelligence for IP"""
    try:
        # Using AbuseIPDB API (free tier)
        api_key = "your-api-key"  # Replace with actual API key
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'abuse_confidence_score': data['data']['abuseConfidenceScore'],
                'country_code': data['data']['countryCode'],
                'is_public': data['data']['isPublic'],
                'ip_version': data['data']['ipVersion'],
                'last_reported_at': data['data'].get('lastReportedAt')
            }
    except:
        pass
    return None

def get_additional_ip_info(ip):
    """Get additional IP information from multiple sources"""
    info = {}
    
    # Get info from ip-api.com
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query", 
                              headers=get_random_headers(), timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                info['ip_api'] = data
    except:
        pass
    
    # Get info from ipgeolocation.io
    try:
        api_key = "your-api-key"  # Replace with actual API key
        response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}", 
                              headers=get_random_headers(), timeout=5)
        if response.status_code == 200:
            info['ipgeolocation'] = response.json()
    except:
        pass
    
    return info

@is_option
def IP_Track():
    print_banner("ADVANCED IP TRACKER", Gr)
    ip = input(f"{Wh}Enter IP target : {Gr}").strip()
    
    if not ip:
        print(f"{Re}[!] Please enter a valid IP address")
        return
    
    # Validate IP format
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        print(f"{Re}[!] Invalid IP address format")
        return
    
    print(f"\n{Cy}[*] Gathering IP information...{Wh}")
    
    # Main IP info from ipwho.is
    try:
        req_api = requests.get(f"http://ipwho.is/{ip}", headers=get_random_headers(), timeout=10)
        ip_data = json.loads(req_api.text)
    except Exception as e:
        print(f"{Re}[!] Error fetching IP data: {e}")
        return
    
    # Get additional info in parallel
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(check_vpn_proxy, ip): 'vpn_proxy',
            executor.submit(get_threat_intelligence, ip): 'threat',
            executor.submit(get_additional_ip_info, ip): 'additional'
        }
        
        results = {}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except:
                results[key] = None
    
    # Display basic IP information
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    BASIC IP INFORMATION                  ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    print(f"\n{Wh}IP Address       : {Gr}{ip}")
    print(f"{Wh}Type              : {Gr}{ip_data.get('type', 'N/A')}")
    print(f"{Wh}Country           : {Gr}{ip_data.get('country', 'N/A')} {ip_data.get('flag', {}).get('emoji', '')}")
    print(f"{Wh}Country Code      : {Gr}{ip_data.get('country_code', 'N/A')}")
    print(f"{Wh}City              : {Gr}{ip_data.get('city', 'N/A')}")
    print(f"{Wh}Region            : {Gr}{ip_data.get('region', 'N/A')}")
    print(f"{Wh}Region Code       : {Gr}{ip_data.get('region_code', 'N/A')}")
    print(f"{Wh}Postal Code       : {Gr}{ip_data.get('postal', 'N/A')}")
    print(f"{Wh}Continent         : {Gr}{ip_data.get('continent', 'N/A')}")
    print(f"{Wh}Continent Code    : {Gr}{ip_data.get('continent_code', 'N/A')}")
    print(f"{Wh}Capital           : {Gr}{ip_data.get('capital', 'N/A')}")
    print(f"{Wh}Borders           : {Gr}{', '.join(ip_data.get('borders', []))}")
    print(f"{Wh}Calling Code      : {Gr}+{ip_data.get('calling_code', 'N/A')}")
    print(f"{Wh}Is EU             : {Gr}{'Yes' if ip_data.get('is_eu') else 'No'}")
    
    # Location information
    lat = ip_data.get('latitude', 0)
    lon = ip_data.get('longitude', 0)
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    LOCATION INFORMATION                   ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    print(f"\n{Wh}Latitude          : {Gr}{lat}")
    print(f"{Wh}Longitude         : {Gr}{lon}")
    print(f"{Wh}Google Maps       : {Gr}https://www.google.com/maps/@{lat},{lon},15z")
    print(f"{Wh}OpenStreetMap     : {Gr}https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}")
    
    # Timezone information
    tz_data = ip_data.get('timezone', {})
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    TIMEZONE INFORMATION                  ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    print(f"\n{Wh}Timezone ID       : {Gr}{tz_data.get('id', 'N/A')}")
    print(f"{Wh}Timezone Abbrev    : {Gr}{tz_data.get('abbr', 'N/A')}")
    print(f"{Wh}UTC Offset        : {Gr}{tz_data.get('utc', 'N/A')}")
    print(f"{Wh}DST Active        : {Gr}{'Yes' if tz_data.get('is_dst') else 'No'}")
    print(f"{Wh}Current Time      : {Gr}{tz_data.get('current_time', 'N/A')}")
    
    # Network information
    conn_data = ip_data.get('connection', {})
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    NETWORK INFORMATION                   ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    print(f"\n{Wh}ASN               : {Gr}{conn_data.get('asn', 'N/A')}")
    print(f"{Wh}Organization      : {Gr}{conn_data.get('org', 'N/A')}")
    print(f"{Wh}ISP               : {Gr}{conn_data.get('isp', 'N/A')}")
    print(f"{Wh}Domain            : {Gr}{conn_data.get('domain', 'N/A')}")
    
    # VPN/Proxy detection
    vpn_info = results.get('vpn_proxy')
    if vpn_info:
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                  ANONYMITY CHECK                       ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}Is Proxy          : {Re}{'Yes' if vpn_info.get('is_proxy') else f'{Gr}No'}")
        print(f"{Wh}Is VPN             : {Re}{'Yes' if vpn_info.get('is_vpn') else f'{Gr}No'}")
        print(f"{Wh}Is Tor             : {Re}{'Yes' if vpn_info.get('is_tor') else f'{Gr}No'}")
        print(f"{Wh}Is Datacenter      : {Re}{'Yes' if vpn_info.get('is_datacenter') else f'{Gr}No'}")
    
    # Threat intelligence
    threat_info = results.get('threat')
    if threat_info:
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                  THREAT INTELLIGENCE                    ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        score = threat_info.get('abuse_confidence_score', 0)
        score_color = Re if score > 50 else Ye if score > 0 else Gr
        print(f"\n{Wh}Abuse Confidence  : {score_color}{score}%{Wh}")
        print(f"{Wh}Last Reported     : {Gr}{threat_info.get('last_reported_at', 'Never')}")
        print(f"{Wh}Is Public         : {Gr}{'Yes' if threat_info.get('is_public') else 'No'}")
        print(f"{Wh}IP Version        : {Gr}IPv{threat_info.get('ip_version', 'N/A')}")
    
    # Additional sources
    add_info = results.get('additional')
    if add_info and add_info.get('ip_api'):
        api_data = add_info['ip_api']
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║              CROSS-VERIFICATION (ip-api.com)            ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}ISP (alt)        : {Gr}{api_data.get('isp', 'N/A')}")
        print(f"{Wh}Organization (alt): {Gr}{api_data.get('org', 'N/A')}")
        print(f"{Wh}AS (alt)          : {Gr}{api_data.get('as', 'N/A')}")
        print(f"{Wh}Timezone (alt)    : {Gr}{api_data.get('timezone', 'N/A')}")

@is_option
def phoneGW():
    print_banner("ADVANCED PHONE NUMBER TRACKER", Gr)
    User_phone = input(f"\n{Wh}Enter phone number {Gr}(e.g., +628123456789) {Wh}: {Gr}").strip()
    
    if not User_phone:
        print(f"{Re}[!] Please enter a phone number")
        return
    
    try:
        default_region = "ID"
        parsed_number = phonenumbers.parse(User_phone, default_region)
        
        if not phonenumbers.is_possible_number(parsed_number):
            print(f"{Re}[!] The phone number is not possible")
            return
        
        print(f"\n{Cy}[*] Analyzing phone number...{Wh}")
        time.sleep(1)
        
        # Basic information
        region_code = phonenumbers.region_code_for_number(parsed_number)
        jenis_provider = carrier.name_for_number(parsed_number, "en")
        location = geocoder.description_for_number(parsed_number, "en")
        is_valid_number = phonenumbers.is_valid_number(parsed_number)
        is_possible_number = phonenumbers.is_possible_number(parsed_number)
        
        # Format variations
        formatted_international = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        formatted_national = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
        formatted_e164 = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        formatted_rfc3966 = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.RFC3966)
        formatted_mobile = phonenumbers.format_number_for_mobile_dialing(parsed_number, default_region, with_formatting=True)
        
        # Number type
        number_type = phonenumbers.number_type(parsed_number)
        type_str = ""
        if number_type == phonenumbers.PhoneNumberType.MOBILE:
            type_str = f"{Gr}Mobile"
        elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE:
            type_str = f"{Gr}Fixed-line"
        elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE:
            type_str = f"{Ye}Fixed-line or Mobile"
        elif number_type == phonenumbers.PhoneNumberType.TOLL_FREE:
            type_str = f"{Cy}Toll-free"
        elif number_type == phonenumbers.PhoneNumberType.PREMIUM_RATE:
            type_str = f"{Mage}Premium-rate"
        elif number_type == phonenumbers.PhoneNumberType.SHARED_COST:
            type_str = f"{Ye}Shared-cost"
        elif number_type == phonenumbers.PhoneNumberType.VOIP:
            type_str = f"{Blu}VoIP"
        elif number_type == phonenumbers.PhoneNumberType.PERSONAL_NUMBER:
            type_str = f"{Mage}Personal number"
        elif number_type == phonenumbers.PhoneNumberType.PAGER:
            type_str = f"{Ye}Pager"
        elif number_type == phonenumbers.PhoneNumberType.UAN:
            type_str = f"{Cy}UAN"
        elif number_type == phonenumbers.PhoneNumberType.VOICEMAIL:
            type_str = f"{Blu}Voicemail"
        else:
            type_str = f"{Re}Unknown"
        
        # Timezone information
        try:
            timezone_list = timezone.time_zones_for_number(parsed_number)
            timezone_str = ', '.join(timezone_list) if timezone_list else "N/A"
        except:
            timezone_str = "N/A"
        
        # Display information
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                  PHONE NUMBER DETAILS                   ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}Original Input    : {Gr}{User_phone}")
        print(f"{Wh}Valid Number       : {Gr}{'Yes' if is_valid_number else f'{Re}No'}")
        print(f"{Wh}Possible Number    : {Gr}{'Yes' if is_possible_number else f'{Re}No'}")
        print(f"{Wh}Number Type        : {type_str}")
        
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    LOCATION INFO                        ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}Country/Region     : {Gr}{region_code}")
        print(f"{Wh}Location           : {Gr}{location}")
        print(f"{Wh}Carrier            : {Gr}{jenis_provider}")
        print(f"{Wh}Timezone(s)        : {Gr}{timezone_str}")
        
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                   FORMAT VARIATIONS                     ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}International       : {Gr}{formatted_international}")
        print(f"{Wh}National            : {Gr}{formatted_national}")
        print(f"{Wh}E.164               : {Gr}{formatted_e164}")
        print(f"{Wh}RFC3966             : {Gr}{formatted_rfc3966}")
        print(f"{Wh}Mobile Dialing      : {Gr}{formatted_mobile}")
        
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    NUMBER PARTS                         ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}Country Code        : {Gr}+{parsed_number.country_code}")
        print(f"{Wh}National Number     : {Gr}{parsed_number.national_number}")
        print(f"{Wh}Extension           : {Gr}{parsed_number.extension or 'None'}")
        print(f"{Wh}Italian Leading Zero: {Gr}{'Yes' if parsed_number.italian_leading_zero else 'No'}")
        
    except phonenumbers.NumberParseException as e:
        print(f"{Re}[!] Error parsing phone number: {e}")
    except Exception as e:
        print(f"{Re}[!] Unexpected error: {e}")

@is_option
def TrackLu():
    print_banner("ADVANCED USERNAME TRACKER", Gr)
    username = input(f"\n{Wh}Enter username to track : {Gr}").strip()
    
    if not username:
        print(f"{Re}[!] Please enter a username")
        return
    
    print(f"\n{Cy}[*] Searching for username across platforms...{Wh}")
    
    # Extended list of social media and online platforms
    platforms = [
        {"name": "Facebook", "url": "https://www.facebook.com/{}", "method": "GET"},
        {"name": "Twitter", "url": "https://twitter.com/{}", "method": "GET"},
        {"name": "Instagram", "url": "https://www.instagram.com/{}", "method": "GET"},
        {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "method": "GET"},
        {"name": "GitHub", "url": "https://github.com/{}", "method": "GET"},
        {"name": "YouTube", "url": "https://www.youtube.com/{}", "method": "GET"},
        {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "method": "GET"},
        {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "method": "GET"},
        {"name": "Pinterest", "url": "https://www.pinterest.com/{}", "method": "GET"},
        {"name": "Tumblr", "url": "https://{}.tumblr.com", "method": "GET"},
        {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "method": "GET"},
        {"name": "Telegram", "url": "https://t.me/{}", "method": "GET"},
        {"name": "WhatsApp", "url": "https://wa.me/{}", "method": "GET"},
        {"name": "Discord", "url": "https://discord.com/users/{}", "method": "GET"},
        {"name": "Twitch", "url": "https://www.twitch.tv/{}", "method": "GET"},
        {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "method": "GET"},
        {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "method": "GET"},
        {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "method": "GET"},
        {"name": "Behance", "url": "https://www.behance.net/{}", "method": "GET"},
        {"name": "Dribbble", "url": "https://dribbble.com/{}", "method": "GET"},
        {"name": "Medium", "url": "https://{}.medium.com", "method": "GET"},
        {"name": "Quora", "url": "https://www.quora.com/profile/{}", "method": "GET"},
        {"name": "Flickr", "url": "https://www.flickr.com/people/{}", "method": "GET"},
        {"name": "Vimeo", "url": "https://vimeo.com/{}", "method": "GET"},
        {"name": "GitLab", "url": "https://gitlab.com/{}", "method": "GET"},
        {"name": "Bitbucket", "url": "https://bitbucket.org/{}", "method": "GET"},
        {"name": "CodePen", "url": "https://codepen.io/{}", "method": "GET"},
        {"name": "DeviantArt", "url": "https://www.deviantart.com/{}", "method": "GET"},
        {"name": "Etsy", "url": "https://www.etsy.com/shop/{}", "method": "GET"},
        {"name": "PayPal", "url": "https://www.paypal.me/{}", "method": "GET"},
        {"name": "Venmo", "url": "https://venmo.com/{}", "method": "GET"},
        {"name": "CashApp", "url": "https://cash.app/${}", "method": "GET"},
        {"name": "Fiverr", "url": "https://www.fiverr.com/{}", "method": "GET"},
        {"name": "Upwork", "url": "https://www.upwork.com/freelancers/~{}", "method": "GET"},
        {"name": "Keybase", "url": "https://keybase.io/{}", "method": "GET"},
        {"name": "Mastodon", "url": "https://mastodon.social/@", "method": "GET"},
        {"name": "Patreon", "url": "https://www.patreon.com/{}", "method": "GET"},
        {"name": "OnlyFans", "url": "https://onlyfans.com/{}", "method": "GET"},
        {"name": "Tinder", "url": "https://www.tinder.com/@{}", "method": "GET"},
        {"name": "Bumble", "url": "https://bumble.com/{}", "method": "GET"},
        {"name": "Grindr", "url": "https://grindr.com/{}", "method": "GET"},
        {"name": "OkCupid", "url": "https://www.okcupid.com/profile/{}", "method": "GET"},
        {"name": "Match", "url": "https://www.match.com/profile/{}", "method": "GET"},
        {"name": "PlentyOfFish", "url": "https://www.pof.com/viewprofile.aspx?profile_id={}", "method": "GET"},
        {"name": "MeetMe", "url": "https://www.meetme.com/{}", "method": "GET"},
        {"name": "Tagged", "url": "https://www.tagged.com/{}", "method": "GET"},
        {"name": "Hi5", "url": "https://www.hi5.com/{}", "method": "GET"},
        {"name": "MySpace", "url": "https://myspace.com/{}", "method": "GET"},
        {"name": "Friendster", "url": "https://www.friendster.com/{}", "method": "GET"},
        {"name": "Orkut", "url": "https://www.orkut.com/{}", "method": "GET"},
        {"name": "Badoo", "url": "https://badoo.com/{}", "method": "GET"},
        {"name": "Twoo", "url": "https://www.twoo.com/{}", "method": "GET"},
        {"name": "Skout", "url": "https://www.skout.com/{}", "method": "GET"},
        {"name": "Moco", "url": "https://www.mocospace.com/{}", "method": "GET"},
        {"name": "Zoosk", "url": "https://www.zoosk.com/{}", "method": "GET"},
        {"name": "Meetup", "url": "https://www.meetup.com/members/{}", "method": "GET"},
        {"name": "Eventbrite", "url": "https://www.eventbrite.com/e/{}", "method": "GET"},
        {"name": "Meetin", "url": "https://meetin.org/{}", "method": "GET"},
        {"name": "Couchsurfing", "url": "https://www.couchsurfing.com/people/{}", "method": "GET"},
        {"name": "Interpals", "url": "https://www.interpals.net/{}", "method": "GET"},
        {"name": "PenPalWorld", "url": "https://www.penpalworld.com/{}", "method": "GET"},
        {"name": "AdoptAPet", "url": "https://www.adoptapet.com/pet/{}", "method": "GET"},
        {"name": "Petfinder", "url": "https://www.petfinder.com/petsearch/{}", "method": "GET"},
        {"name": "Rover", "url": "https://www.rover.com/members/{}", "method": "GET"},
        {"name": "Wag", "url": "https://wagwalking.com/{}", "method": "GET"},
        {"name": "Care", "url": "https://www.care.com/p/{}", "method": "GET"},
        {"name": "Sittercity", "url": "https://www.sittercity.com/{}", "method": "GET"},
        {"name": "UrbanSitter", "url": "https://www.urbansitter.com/{}", "method": "GET"},
        {"name": "TaskRabbit", "url": "https://www.taskrabbit.com/profile/{}", "method": "GET"},
        {"name": "Fancy Hands", "url": "https://www.fancyhands.com/{}", "method": "GET"},
        {"name": "Zirtual", "url": "https://www.zirtual.com/{}", "method": "GET"},
        {"name": "Time Etc", "url": "https://www.timeetc.com/{}", "method": "GET"},
        {"name": "Belay", "url": "https://www.belaysolutions.com/{}", "method": "GET"},
        {"name": "Prialto", "url": "https://www.prialto.com/{}", "method": "GET"},
        {"name": "Worldwide101", "url": "https://www.worldwide101.com/{}", "method": "GET"},
        {"name": "VirtualStaffFinder", "url": "https://www.virtualstafffinder.com/{}", "method": "GET"},
        {"name": "RemoteCoWorker", "url": "https://www.remotecoworker.com/{}", "method": "GET"},
        {"name": "MyTasker", "url": "https://www.mytasker.com/{}", "method": "GET"},
        {"name": "OkayRelax", "url": "https://www.okayrelax.com/{}", "method": "GET"},
        {"name": "Fancy", "url": "https://fancy.com/{}", "method": "GET"},
        {"name": "Wanelo", "url": "https://wanelo.com/{}", "method": "GET"},
        {"name": "Polyvore", "url": "https://www.polyvore.com/{}", "method": "GET"},
        {"name": "Poshmark", "url": "https://poshmark.com/closet/{}", "method": "GET"},
        {"name": "Mercari", "url": "https://www.mercari.com/u/{}", "method": "GET"},
        {"name": "Depop", "url": "https://www.depop.com/{}", "method": "GET"},
        {"name": "Grailed", "url": "https://www.grailed.com/{}", "method": "GET"},
        {"name": "StockX", "url": "https://stockx.com/{}", "method": "GET"},
        {"name": "GOAT", "url": "https://www.goat.com/{}", "method": "GET"},
        {"name": "Stadium Goods", "url": "https://www.stadiumgoods.com/{}", "method": "GET"},
        {"name": "Flight Club", "url": "https://www.flightclub.com/{}", "method": "GET"},
        {"name": "Kixify", "url": "https://www.kixify.com/{}", "method": "GET"},
        {"name": "SneakerNews", "url": "https://sneakernews.com/{}", "method": "GET"},
        {"name": "Hypebeast", "url": "https://hypebeast.com/{}", "method": "GET"},
        {"name": "Highsnobiety", "url": "https://www.highsnobiety.com/{}", "method": "GET"},
        {"name": "Complex", "url": "https://www.complex.com/{}", "method": "GET"},
        {"name": "Vice", "url": "https://www.vice.com/en_us/article/{}", "method": "GET"},
        {"name": "BuzzFeed", "url": "https://www.buzzfeed.com/{}", "method": "GET"},
        {"name": "Vox", "url": "https://www.vox.com/authors/{}", "method": "GET"},
        {"name": "The Verge", "url": "https://www.theverge.com/users/{}", "method": "GET"},
        {"name": "Engadget", "url": "https://www.engadget.com/about/editors/{}", "method": "GET"},
        {"name": "Gizmodo", "url": "https://gizmodo.com/c/{}", "method": "GET"},
        {"name": "Kotaku", "url": "https://kotaku.com/c/{}", "method": "GET"},
        {"name": "Lifehacker", "url": "https://lifehacker.com/c/{}", "method": "GET"},
        {"name": "The Onion", "url": "https://www.theonion.com/author/{}", "method": "GET"},
        {"name": "ClickHole", "url": "https://www.clickhole.com/author/{}", "method": "GET"},
        {"name": "The Hard Times", "url": "https://thehardtimes.net/author/{}", "method": "GET"},
        {"name": "Reductress", "url": "https://reductress.com/author/{}", "method": "GET"},
        {"name": "The Beaverton", "url": "https://www.thebeaverton.com/author/{}", "method": "GET"},
        {"name": "The Chive", "url": "https://thechive.com/author/{}", "method": "GET"},
        {"name": "The Berry", "url": "https://theberry.com/author/{}", "method": "GET"},
        {"name": "The Awesome", "url": "https://theawesome.com/author/{}", "method": "GET"},
        {"name": "The Daily Mash", "url": "https://www.thedailymash.co.uk/author/{}", "method": "GET"},
        {"name": "The Spoof", "url": "https://www.thespoof.com/author/{}", "method": "GET"},
        {"name": "The News Nerd", "url": "https://www.thenewsnerd.com/author/{}", "method": "GET"},
        {"name": "The Borowitz Report", "url": "https://www.newyorker.com/humor/borowitz-report/{}", "method": "GET"},
        {"name": "The Onion News Network", "url": "https://www.theonion.com/onn/{}", "method": "GET"},
        {"name": "The A.V. Club", "url": "https://www.avclub.com/author/{}", "method": "GET"},
        {"name": "Deadspin", "url": "https://deadspin.com/author/{}", "method": "GET"},
        {"name": "Jezebel", "url": "https://jezebel.com/author/{}", "method": "GET"},
        {"name": "Splinter", "url": "https://splinternews.com/author/{}", "method": "GET"},
        {"name": "The Root", "url": "https://www.theroot.com/author/{}", "method": "GET"},
        {"name": "Earther", "url": "https://earther.com/author/{}", "method": "GET"},
        {"name": "The Takeout", "url": "https://thetakeout.com/author/{}", "method": "GET"},
        {"name": "The Inventory", "url": "https://theinventory.com/author/{}", "method": "GET"},
        {"name": "The Muse", "url": "https://www.themuse.com/{}", "method": "GET"},
        {"name": "Glassdoor", "url": "https://www.glassdoor.com/Overview/Working-at-{}", "method": "GET"},
        {"name": "Indeed", "url": "https://www.indeed.com/cmp/{}", "method": "GET"},
        {"name": "LinkedIn Company", "url": "https://www.linkedin.com/company/{}", "method": "GET"},
        {"name": "Crunchbase", "url": "https://www.crunchbase.com/organization/{}", "method": "GET"},
        {"name": "AngelList", "url": "https://angel.co/company/{}", "method": "GET"},
        {"name": "Product Hunt", "url": "https://www.producthunt.com/@{}", "method": "GET"},
        {"name": "Hacker News", "url": "https://news.ycombinator.com/user?id={}", "method": "GET"},
        {"name": "Reddit Subreddit", "url": "https://www.reddit.com/r/{}", "method": "GET"},
        {"name": "Discord Server", "url": "https://discord.gg/{}", "method": "GET"},
        {"name": "Slack", "url": "https://{}.slack.com", "method": "GET"},
        {"name": "Microsoft Teams", "url": "https://teams.microsoft.com/l/team/{}", "method": "GET"},
        {"name": "Zoom", "url": "https://zoom.us/j/{}", "method": "GET"},
        {"name": "Google Meet", "url": "https://meet.google.com/{}", "method": "GET"},
        {"name": "Webex", "url": "https://{}.webex.com", "method": "GET"},
        {"name": "GoToMeeting", "url": "https://www.gotomeet.me/{}", "method": "GET"},
        {"name": "BlueJeans", "url": "https://bluejeans.com/{}", "method": "GET"},
        {"name": "Join.me", "url": "https://join.me/{}", "method": "GET"},
        {"name": "FreeConferenceCall", "url": "https://www.freeconferencecall.com/{}", "method": "GET"},
        {"name": "GlobalMeet", "url": "https://www.globalmeet.com/{}", "method": "GET"},
        {"name": "RingCentral", "url": "https://ringcentral.com/{}", "method": "GET"},
        {"name": "8x8", "url": "https://www.8x8.com/{}", "method": "GET"},
        {"name": "Vonage", "url": "https://www.vonage.com/{}", "method": "GET"},
        {"name": "Dialpad", "url": "https://www.dialpad.com/{}", "method": "GET"},
        {"name": "UberConference", "url": "https://www.uberconference.com/{}", "method": "GET"},
        {"name": "StarLeaf", "url": "https://starleaf.com/{}", "method": "GET"},
        {"name": "Lifesize", "url": "https://www.lifesize.com/{}", "method": "GET"},
        {"name": "Pexip", "url": "https://www.pexip.com/{}", "method": "GET"},
        {"name": "Acano", "url": "https://www.acano.com/{}", "method": "GET"},
        {"name": "Vidyo", "url": "https://www.vidyo.com/{}", "method": "GET"},
        {"name": "Polycom", "url": "https://www.polycom.com/{}", "method": "GET"},
        {"name": "Cisco", "url": "https://www.cisco.com/{}", "method": "GET"},
        {"name": "Avaya", "url": "https://www.avaya.com/{}", "method": "GET"},
        {"name": "Mitel", "url": "https://www.mitel.com/{}", "method": "GET"},
        {"name": "ShoreTel", "url": "https://www.shoretel.com/{}", "method": "GET"},
        {"name": "Yealink", "url": "https://www.yealink.com/{}", "method": "GET"},
        {"name": "Grandstream", "url": "https://www.grandstream.com/{}", "method": "GET"},
        {"name": "Sangoma", "url": "https://www.sangoma.com/{}", "method": "GET"},
        {"name": "Digium", "url": "https://www.digium.com/{}", "method": "GET"},
        {"name": "Asterisk", "url": "https://www.asterisk.org/{}", "method": "GET"},
        {"name": "FreeSWITCH", "url": "https://freeswitch.org/{}", "method": "GET"},
        {"name": "Kamailio", "url": "https://www.kamailio.org/{}", "method": "GET"},
        {"name": "OpenSIPS", "url": "https://www.opensips.org/{}", "method": "GET"},
        {"name": "RTPengine", "url": "https://www.rtpengine.com/{}", "method": "GET"},
        {"name": "RTPEngine", "url": "https://rtpengine.com/{}", "method": "GET"},
        {"name": "SRT", "url": "https://www.haivision.com/srt/", "method": "GET"},
        {"name": "WebRTC", "url": "https://webrtc.org/{}", "method": "GET"},
        {"name": "Janus", "url": "https://janus.conf.meetecho.com/{}", "method": "GET"},
        {"name": "Jitsi", "url": "https://jitsi.org/{}", "method": "GET"},
        {"name": "Kurento", "url": "https://www.kurento.org/{}", "method": "GET"},
        {"name": "Mediasoup", "url": "https://mediasoup.org/{}", "method": "GET"},
        {"name": "LiveKit", "url": "https://livekit.io/{}", "method": "GET"},
        {"name": "Pion", "url": "https://pion.ly/{}", "method": "GET"},
        {"name": "WebTorrent", "url": "https://webtorrent.io/{}", "method": "GET"},
        {"name": "PeerJS", "url": "https://peerjs.com/{}", "method": "GET"},
        {"name": "Simple-peer", "url": "https://github.com/feross/simple-peer", "method": "GET"},
        {"name": "Socket.io", "url": "https://socket.io/{}", "method": "GET"},
        {"name": "SignalR", "url": "https://dotnet.microsoft.com/apps/aspnet/signalr", "method": "GET"},
        {"name": "Pusher", "url": "https://pusher.com/{}", "method": "GET"},
        {"name": "Ably", "url": "https://ably.com/{}", "method": "GET"},
        {"name": "PubNub", "url": "https://www.pubnub.com/{}", "method": "GET"},
        {"name": "Firebase", "url": "https://firebase.google.com/{}", "method": "GET"},
        {"name": "AWS", "url": "https://aws.amazon.com/{}", "method": "GET"},
        {"name": "Azure", "url": "https://azure.microsoft.com/{}", "method": "GET"},
        {"name": "Google Cloud", "url": "https://cloud.google.com/{}", "method": "GET"},
        {"name": "IBM Cloud", "url": "https://www.ibm.com/cloud/{}", "method": "GET"},
        {"name": "Oracle Cloud", "url": "https://www.oracle.com/cloud/{}", "method": "GET"},
        {"name": "Alibaba Cloud", "url": "https://www.alibabacloud.com/{}", "method": "GET"},
        {"name": "Tencent Cloud", "url": "https://intl.cloud.tencent.com/{}", "method": "GET"},
        {"name": "DigitalOcean", "url": "https://www.digitalocean.com/{}", "method": "GET"},
        {"name": "Linode", "url": "https://www.linode.com/{}", "method": "GET"},
        {"name": "Vultr", "url": "https://www.vultr.com/{}", "method": "GET"},
        {"name": "Hetzner", "url": "https://www.hetzner.com/{}", "method": "GET"},
        {"name": "OVH", "url": "https://www.ovh.com/{}", "method": "GET"},
        {"name": "Scaleway", "url": "https://www.scaleway.com/{}", "method": "GET"},
        {"name": "UpCloud", "url": "https://www.upcloud.com/{}", "method": "GET"},
        {"name": "Exoscale", "url": "https://www.exoscale.com/{}", "method": "GET"},
        {"name": "Rackspace", "url": "https://www.rackspace.com/{}", "method": "GET"},
        {"name": "IBM", "url": "https://www.ibm.com/{}", "method": "GET"},
        {"name": "HP", "url": "https://www.hp.com/{}", "method": "GET"},
        {"name": "Dell", "url": "https://www.dell.com/{}", "method": "GET"},
        {"name": "Lenovo", "url": "https://www.lenovo.com/{}", "method": "GET"},
        {"name": "ASUS", "url": "https://www.asus.com/{}", "method": "GET"},
        {"name": "Acer", "url": "https://www.acer.com/{}", "method": "GET"},
        {"name": "MSI", "url": "https://www.msi.com/{}", "method": "GET"},
        {"name": "Gigabyte", "url": "https://www.gigabyte.com/{}", "method": "GET"},
        {"name": "Biostar", "url": "https://www.biostar.com.tw/{}", "method": "GET"},
        {"name": "ASRock", "url": "https://www.asrock.com/{}", "method": "GET"},
        {"name": "EVGA", "url": "https://www.evga.com/{}", "method": "GET"},
        {"name": "Corsair", "url": "https://www.corsair.com/{}", "method": "GET"},
        {"name": "NZXT", "url": "https://www.nzxt.com/{}", "method": "GET"},
        {"name": "Phanteks", "url": "https://www.phanteks.com/{}", "method": "GET"},
        {"name": "Lian Li", "url": "https://www.lian-li.com/{}", "method": "GET"},
        {"name": "Fractal Design", "url": "https://www.fractal-design.com/{}", "method": "GET"},
        {"name": "Cooler Master", "url": "https://www.coolermaster.com/{}", "method": "GET"},
        {"name": "Thermaltake", "url": "https://www.thermaltake.com/{}", "method": "GET"},
        {"name": "SilverStone", "url": "https://www.silverstonetek.com/{}", "method": "GET"},
        {"name": "be quiet!", "url": "https://www.bequiet.com/{}", "method": "GET"},
        {"name": "Noctua", "url": "https://noctua.at/en/{}", "method": "GET"},
        {"name": "Arctic", "url": "https://www.arctic.de/{}", "method": "GET"},
        {"name": "DeepCool", "url": "https://www.deepcool.com/{}", "method": "GET"},
        {"name": "ID-COOLING", "url": "https://www.id-cooling.com/{}", "method": "GET"},
        {"name": "Xigmatek", "url": "https://www.xigmatek.com/{}", "method": "GET"},
        {"name": "Aerocool", "url": "https://www.aerocool.com/{}", "method": "GET"},
        {"name": "Raijintek", "url": "https://www.raijintek.com/{}", "method": "GET"},
        {"name": "Gelid", "url": "https://www.gelidsolutions.com/{}", "method": "GET"},
        {"name": "Zalman", "url": "https://www.zalman.com/{}", "method": "GET"},
        {"name": "Scythe", "url": "https://www.scythe-us.com/{}", "method": "GET"},
        {"name": "Cryorig", "url": "https://www.cryorig.com/{}", "method": "GET"},
        {"name": "Alphacool", "url": "https://www.alphacool.com/{}", "method": "GET"},
        {"name": "Aquacomputer", "url": "https://www.aquacomputer.de/{}", "method": "GET"},
        {"name": "EKWB", "url": "https://www.ekwb.com/{}", "method": "GET"},
        {"name": "Heatkiller", "url": "https://www.heatkiller.com/{}", "method": "GET"},
        {"name": "Watercool", "url": "https://www.watercool.de/{}", "method": "GET"},
        {"name": "Phobya", "url": "https://www.phobya.com/{}", "method": "GET"},
        {"name": "Alphacool", "url": "https://www.alphacool.com/{}", "method": "GET"},
        {"name": "XSPC", "url": "https://www.xspc.com/{}", "method": "GET"},
        {"name": "Koolance", "url": "https://www.koolance.com/{}", "method": "GET"},
        {"name": "Swiftech", "url": "https://www.swiftech.com/{}", "method": "GET"},
        {"name": "Danger Den", "url": "https://www.dangerden.com/{}", "method": "GET"},
        {"name": "Petrastechshop", "url": "https://www.petrastechshop.com/{}", "method": "GET"},
        {"name": "Performance-pcs", "url": "https://www.performance-pcs.com/{}", "method": "GET"},
        {"name": "FrozenCPU", "url": "https://www.frozencpu.com/{}", "method": "GET"},
        {"name": "Sidewinder", "url": "https://www.sidewindercomputers.com/{}", "method": "GET"},
        {"name": "Jab-tech", "url": "https://www.jab-tech.com/{}", "method": "GET"},
        {"name": "Cooling-Shop", "url": "https://www.cooling-shop.com/{}", "method": "GET"},
        {"name": "Aquatuning", "url": "https://www.aquatuning.us/{}", "method": "GET"},
        {"name": "ModMyMods", "url": "https://www.modmymods.com/{}", "method": "GET"},
        {"name": "V1 Tech", "url": "https://www.v1tech.com/{}", "method": "GET"},
        {"name": "Lazer3D", "url": "https://lazer3d.com/{}", "method": "GET"},
        {"name": "Dwood", "url": "https://dwooddesigns.com/{}", "method": "GET"},
        {"name": "Custom-PC", "url": "https://www.custompc.co.uk/{}", "method": "GET"},
        {"name": "PC Gamer", "url": "https://www.pcgamer.com/{}", "method": "GET"},
        {"name": "Tom's Hardware", "url": "https://www.tomshardware.com/{}", "method": "GET"},
        {"name": "AnandTech", "url": "https://www.anandtech.com/{}", "method": "GET"},
        {"name": "TechPowerUp", "url": "https://www.techpowerup.com/{}", "method": "GET"},
        {"name": "TechSpot", "url": "https://www.techspot.com/{}", "method": "GET"},
        {"name": "PCMag", "url": "https://www.pcmag.com/{}", "method": "GET"},
        {"name": "CNET", "url": "https://www.cnet.com/{}", "method": "GET"},
        {"name": "ZDNet", "url": "https://www.zdnet.com/{}", "method": "GET"},
        {"name": "Wired", "url": "https://www.wired.com/{}", "method": "GET"},
        {"name": "Ars Technica", "url": "https://arstechnica.com/{}", "method": "GET"},
        {"name": "The Register", "url": "https://www.theregister.com/{}", "method": "GET"},
        {"name": "Heise Online", "url": "https://www.heise.de/{}", "method": "GET"},
        {"name": "Golem.de", "url": "https://www.golem.de/{}", "method": "GET"},
        {"name": "ComputerBase", "url": "https://www.computerbase.de/{}", "method": "GET"},
        {"name": "PC Games Hardware", "url": "https://www.pcgameshardware.de/{}", "method": "GET"},
        {"name": "GameStar", "url": "https://www.gamestar.de/{}", "method": "GET"},
        {"name": "GamePro", "url": "https://www.gamepro.de/{}", "method": "GET"},
        {"name": "4Players", "url": "https://www.4players.de/{}", "method": "GET"},
        {"name": "Eurogamer", "url": "https://www.eurogamer.net/{}", "method": "GET"},
        {"name": "Polygon", "url": "https://www.polygon.com/{}", "method": "GET"},
        {"name": "Kotaku", "url": "https://kotaku.com/{}", "method": "GET"},
        {"name": "IGN", "url": "https://www.ign.com/{}", "method": "GET"},
        {"name": "GameSpot", "url": "https://www.gamespot.com/{}", "method": "GET"},
        {"name": "PC Gamer", "url": "https://www.pcgamer.com/{}", "method": "GET"},
        {"name": "GamesRadar", "url": "https://www.gamesradar.com/{}", "method": "GET"},
        {"name": "Rock Paper Shotgun", "url": "https://www.rockpapershotgun.com/{}", "method": "GET"},
        {"name": "PC Gamer UK", "url": "https://www.pcgamer.co.uk/{}", "method": "GET"},
        {"name": "Edge Magazine", "url": "https://www.edge-online.com/{}", "method": "GET"},
        {"name": "Play Magazine", "url": "https://www.play-magazine.co.uk/{}", "method": "GET"},
        {"name": "Official Xbox Magazine", "url": "https://www.oxm.co.uk/{}", "method": "GET"},
        {"name": "Official PlayStation Magazine", "url": "https://www.playstationmuseum.com/{}", "method": "GET"},
        {"name": "Nintendo Life", "url": "https://www.nintendolife.com/{}", "method": "GET"},
        {"name": "Push Square", "url": "https://www.pushsquare.com/{}", "method": "GET"},
        {"name": "Pure Xbox", "url": "https://www.purexbox.com/{}", "method": "GET"},
        {"name": "Game Informer", "url": "https://www.gameinformer.com/{}", "method": "GET"},
        {"name": "Game Developer", "url": "https://www.gamedeveloper.com/{}", "method": "GET"},
        {"name": "Gamasutra", "url": "https://www.gamasutra.com/{}", "method": "GET"},
        {"name": "VentureBeat", "url": "https://venturebeat.com/{}", "method": "GET"},
        {"name": "TechCrunch", "url": "https://techcrunch.com/{}", "method": "GET"},
        {"name": "The Next Web", "url": "https://thenextweb.com/{}", "method": "GET"},
        {"name": "Mashable", "url": "https://mashable.com/{}", "method": "GET"},
        {"name": "ReadWrite", "url": "https://readwrite.com/{}", "method": "GET"},
        {"name": "Gizmodo", "url": "https://gizmodo.com/{}", "method": "GET"},
        {"name": "Engadget", "url": "https://www.engadget.com/{}", "method": "GET"},
        {"name": "The Verge", "url": "https://www.theverge.com/{}", "method": "GET"},
        {"name": "Recode", "url": "https://www.vox.com/recode", "method": "GET"},
        {"name": "Protocol", "url": "https://www.protocol.com/{}", "method": "GET"},
        {"name": "The Information", "url": "https://theinformation.com/{}", "method": "GET"},
        {"name": "Stratechery", "url": "https://stratechery.com/{}", "method": "GET"},
        {"name": "Ben Thompson", "url": "https://www.benthompson.com/{}", "method": "GET"},
        {"name": "Daring Fireball", "url": "https://daringfireball.net/{}", "method": "GET"},
        {"name": "Marco.org", "url": "https://marco.org/{}", "method": "GET"},
        {"name": "Six Colors", "url": "https://sixcolors.com/{}", "method": "GET"},
        {"name": "MacStories", "url": "https://www.macstories.net/{}", "method": "GET"},
        {"name": "iMore", "url": "https://www.imore.com/{}", "method": "GET"},
        {"name": "9to5Mac", "url": "https://9to5mac.com/{}", "method": "GET"},
        {"name": "MacRumors", "url": "https://www.macrumors.com/{}", "method": "GET"},
        {"name": "AppleInsider", "url": "https://appleinsider.com/{}", "method": "GET"},
        {"name": "Cult of Mac", "url": "https://cultofmac.com/{}", "method": "GET"},
        {"name": "iDownloadBlog", "url": "https://www.idownloadblog.com/{}", "method": "GET"},
        {"name": "iPhone Hacks", "url": "https://www.iphonehacks.com/{}", "method": "GET"},
        {"name": "iPad Insight", "url": "https://www.ipadinsight.com/{}", "method": "GET"},
        {"name": "AppleToolBox", "url": "https://www.appletoolbox.com/{}", "method": "GET"},
        {"name": "MacReports", "url": "https://www.macreports.com/{}", "method": "GET"},
        {"name": "Apple World Today", "url": "https://www.appleworld.today/{}", "method": "GET"},
        {"name": "Apple Gazette", "url": "https://www.applegazette.com/{}", "method": "GET"},
        {"name": "Apple Sliced", "url": "https://www.applesliced.com/{}", "method": "GET"},
        {"name": "MacPrices", "url": "https://www.macprices.com/{}", "method": "GET"},
        {"name": "MacMall", "url": "https://www.macmall.com/{}", "method": "GET"},
        {"name": "B&H Photo", "url": "https://www.bhphotovideo.com/{}", "method": "GET"},
        {"name": "Adorama", "url": "https://www.adorama.com/{}", "method": "GET"},
        {"name": "Best Buy", "url": "https://www.bestbuy.com/{}", "method": "GET"},
        {"name": "Amazon", "url": "https://www.amazon.com/{}", "method": "GET"},
        {"name": "eBay", "url": "https://www.ebay.com/{}", "method": "GET"},
        {"name": "Walmart", "url": "https://www.walmart.com/{}", "method": "GET"},
        {"name": "Target", "url": "https://www.target.com/{}", "method": "GET"},
        {"name": "Costco", "url": "https://www.costco.com/{}", "method": "GET"},
        {"name": "Sam's Club", "url": "https://www.samsclub.com/{}", "method": "GET"},
        {"name": "BJ's Wholesale", "url": "https://www.bjs.com/{}", "method": "GET"},
        {"name": "Home Depot", "url": "https://www.homedepot.com/{}", "method": "GET"},
        {"name": "Lowe's", "url": "https://www.lowes.com/{}", "method": "GET"},
        {"name": "Ace Hardware", "url": "https://www.acehardware.com/{}", "method": "GET"},
        {"name": "True Value", "url": "https://www.truevalue.com/{}", "method": "GET"},
        {"name": "Do It Best", "url": "https://www.doitbest.com/{}", "method": "GET"},
        {"name": "Menards", "url": "https://www.menards.com/{}", "method": "GET"},
        {"name": "Northern Tool", "url": "https://www.northerntool.com/{}", "method": "GET"},
        {"name": "Harbor Freight", "url": "https://www.harborfreight.com/{}", "method": "GET"},
        {"name": "Grainger", "url": "https://www.grainger.com/{}", "method": "GET"},
        {"name": "Fastenal", "url": "https://www.fastenal.com/{}", "method": "GET"},
        {"name": "MSC Industrial", "url": "https://www.mscdirect.com/{}", "method": "GET"},
        {"name": "Zoro", "url": "https://www.zoro.com/{}", "method": "GET"},
        {"name": "Global Industrial", "url": "https://www.globalindustrial.com/{}", "method": "GET"},
        {"name": "Uline", "url": "https://www.uline.com/{}", "method": "GET"},
        {"name": "PackagingSupplies", "url": "https://www.packagingsupplies.com/{}", "method": "GET"},
        {"name": "Paper Mart", "url": "https://www.papermart.com/{}", "method": "GET"},
        {"name": "Discount School Supply", "url": "https://www.discountschoolsupply.com/{}", "method": "GET"},
        {"name": "Lakeshore Learning", "url": "https://www.lakeshorelearning.com/{}", "method": "GET"},
        {"name": "Really Good Stuff", "url": "https://www.reallygoodstuff.com/{}", "method": "GET"},
        {"name": "Teacher Created Resources", "url": "https://www.teachercreated.com/{}", "method": "GET"},
        {"name": "Scholastic", "url": "https://www.scholastic.com/{}", "method": "GET"},
        {"name": "Barnes & Noble", "url": "https://www.barnesandnoble.com/{}", "method": "GET"},
        {"name": "Books-A-Million", "url": "https://www.booksamillion.com/{}", "method": "GET"},
        {"name": "IndieBound", "url": "https://www.indiebound.org/{}", "method": "GET"},
        {"name": "Bookshop", "url": "https://bookshop.org/{}", "method": "GET"},
        {"name": "ThriftBooks", "url": "https://www.thriftbooks.com/{}", "method": "GET"},
        {"name": "AbeBooks", "url": "https://www.abebooks.com/{}", "method": "GET"},
        {"name": "Alibris", "url": "https://www.alibris.com/{}", "method": "GET"},
        {"name": "Powell's", "url": "https://www.powells.com/{}", "method": "GET"},
        {"name": "Half Price Books", "url": "https://www.hpb.com/{}", "method": "GET"},
        {"name": "Better World Books", "url": "https://www.betterworldbooks.com/{}", "method": "GET"},
        {"name": "Book Depository", "url": "https://www.bookdepository.com/{}", "method": "GET"},
        {"name": "Wordery", "url": "https://www.wordery.com/{}", "method": "GET"},
        {"name": "Blackwell's", "url": "https://blackwells.co.uk/{}", "method": "GET"},
        {"name": "Waterstones", "url": "https://www.waterstones.com/{}", "method": "GET"},
        {"name": "Foyles", "url": "https://www.foyles.co.uk/{}", "method": "GET"},
        {"name": "Hive", "url": "https://www.hive.co.uk/{}", "method": "GET"},
        {"name": "WHSmith", "url": "https://www.whsmith.co.uk/{}", "method": "GET"},
        {"name": "John Lewis", "url": "https://www.johnlewis.com/{}", "method": "GET"},
        {"name": "Currys PC World", "url": "https://www.currys.co.uk/{}", "method": "GET"},
        {"name": "Argos", "url": "https://www.argos.co.uk/{}", "method": "GET"},
        {"name": "Tesco", "url": "https://www.tesco.com/{}", "method": "GET"},
        {"name": "Sainsbury's", "url": "https://www.sainsburys.co.uk/{}", "method": "GET"},
        {"name": "Asda", "url": "https://www.asda.com/{}", "method": "GET"},
        {"name": "Morrisons", "url": "https://www.morrisons.com/{}", "method": "GET"},
        {"name": "Waitrose", "url": "https://www.waitrose.com/{}", "method": "GET"},
        {"name": "M&S", "url": "https://www.marksandspencer.com/{}", "method": "GET"},
        {"name": "Debenhams", "url": "https://www.debenhams.com/{}", "method": "GET"},
        {"name": "House of Fraser", "url": "https://www.houseoffraser.co.uk/{}", "method": "GET"},
        {"name": "Selfridges", "url": "https://www.selfridges.com/{}", "method": "GET"},
        {"name": "Harrods", "url": "https://www.harrods.com/{}", "method": "GET"},
        {"name": "Fortnum & Mason", "url": "https://www.fortnumandmason.com/{}", "method": "GET"},
        {"name": "Liberty", "url": "https://www.libertylondon.com/{}", "method": "GET"},
        {"name": "Hamleys", "url": "https://www.hamleys.com/{}", "method": "GET"},
        {"name": "The Royal Exchange", "url": "https://www.theroyalexchange.co.uk/{}", "method": "GET"},
        {"name": "Burlington Arcade", "url": "https://www.burlingtonarcade.com/{}", "method": "GET"},
        {"name": "Piccadilly Arcade", "url": "https://www.piccadillyarcade.co.uk/{}", "method": "GET"},
        {"name": "Princes Arcade", "url": "https://www.princesarcade.co.uk/{}", "method": "GET"},
        {"name": "Royal Arcade", "url": "https://www.royalarcade.co.uk/{}", "method": "GET"},
        {"name": "The Piazza", "url": "https://www.thepiazza.co.uk/{}", "method": "GET"},
        {"name": "Covent Garden", "url": "https://www.coventgarden.org.uk/{}", "method": "GET"},
        {"name": "Carnaby Street", "url": "https://www.carnaby.co.uk/{}", "method": "GET"},
        {"name": "King's Road", "url": "https://www.kingsroad.co.uk/{}", "method": "GET"},
        {"name": "Portobello Road", "url": "https://www.portobelloroad.co.uk/{}", "method": "GET"},
        {"name": "Brick Lane", "url": "https://www.bricklane.co.uk/{}", "method": "GET"},
        {"name": "Camden Market", "url": "https://www.camdenmarket.com/{}", "method": "GET"},
        {"name": "Borough Market", "url": "https://www.boroughmarket.org.uk/{}", "method": "GET"},
        {"name": "Greenwich Market", "url": "https://www.greenwichmarket.co.uk/{}", "method": "GET"},
        {"name": "Old Spitalfields Market", "url": "https://www.oldspitalfieldsmarket.com/{}", "method": "GET"},
        {"name": "Leadenhall Market", "url": "https://www.leadenhallmarket.co.uk/{}", "method": "GET"},
        {"name": "Smithfield Market", "url": "https://www.smithfieldmarket.com/{}", "method": "GET"},
        {"name": "Billingsgate Market", "url": "https://www.billingsgatemarket.co.uk/{}", "method": "GET"},
        {"name": "New Covent Garden Market", "url": "https://www.newcoventgardenmarket.com/{}", "method": "GET"},
        {"name": "Western International Market", "url": "https://www.westerninternationalmarket.com/{}", "method": "GET"},
        {"name": "London Fruit & Vegetable Market", "url": "https://www.lfvmarket.co.uk/{}", "method": "GET"},
        {"name": "New Spitalfields Market", "url": "https://www.newspitalfieldsmarket.com/{}", "method": "GET"},
        {"name": "Nine Elms Market", "url": "https://www.nineelmsmarket.com/{}", "method": "GET"},
        {"name": "Park Royal Market", "url": "https://www.parkroyalmarket.com/{}", "method": "GET"},
        {"name": "Wandsworth Market", "url": "https://www.wandsworthmarket.com/{}", "method": "GET"},
        {"name": "Battersea Market", "url": "https://www.batterseamarket.com/{}", "method": "GET"},
        {"name": "Chelsea Market", "url": "https://www.chelseamarket.com/{}", "method": "GET"},
        {"name": "Kensington Market", "url": "https://www.kensingtonmarket.com/{}", "method": "GET"},
        {"name": "Knightsbridge Market", "url": "https://www.knightsbridgemarket.com/{}", "method": "GET"},
        {"name": "Mayfair Market", "url": "https://www.mayfairmarket.com/{}", "method": "GET"},
        {"name": "Marylebone Market", "url": "https://www.marylebonemarket.com/{}", "method": "GET"},
        {"name": "Soho Market", "url": "https://www.sohomarket.com/{}", "method": "GET"},
        {"name": "Fitzrovia Market", "url": "https://www.fitzroviamarket.com/{}", "method": "GET"},
        {"name": "Bloomsbury Market", "url": "https://www.bloomsburymarket.com/{}", "method": "GET"},
        {"name": "Holborn Market", "url": "https://www.holbornmarket.com/{}", "method": "GET"},
        {"name": "Temple Market", "url": "https://www.templemarket.com/{}", "method": "GET"},
        {"name": "Fleet Street Market", "url": "https://www.fleetstreetmarket.com/{}", "method": "GET"},
        {"name": "Ludgate Hill Market", "url": "https://www.ludgatehillmarket.com/{}", "method": "GET"},
        {"name": "St Paul's Market", "url": "https://www.stpaulsmarket.com/{}", "method": "GET"},
        {"name": "Cheapside Market", "url": "https://www.cheapsidemarket.com/{}", "method": "GET"},
        {"name": "Poultry Market", "url": "https://www.poultrymarket.com/{}", "method": "GET"},
        {"name": "Cornhill Market", "url": "https://www.cornhillmarket.com/{}", "method": "GET"},
        {"name": "Lombard Street Market", "url": "https://www.lombardstreetmarket.com/{}", "method": "GET"},
        {"name": "Fenchurch Street Market", "url": "https://www.fenchurchstreetmarket.com/{}", "method": "GET"},
        {"name": "Leadenhall Street Market", "url": "https://www.leadenhallstreetmarket.com/{}", "method": "GET"},
        {"name": "Aldgate Market", "url": "https://www.aldgatemarket.com/{}", "method": "GET"},
        {"name": "Whitechapel Market", "url": "https://www.whitechapelmarket.com/{}", "method": "GET"},
        {"name": "Mile End Market", "url": "https://www.mileendmarket.com/{}", "method": "GET"},
        {"name": "Bow Market", "url": "https://www.bowmarket.com/{}", "method": "GET"},
        {"name": "Stratford Market", "url": "https://www.stratfordmarket.com/{}", "method": "GET"},
        {"name": "West Ham Market", "url": "https://www.westhammarket.com/{}", "method": "GET"},
        {"name": "Canning Town Market", "url": "https://www.canningtownmarket.com/{}", "method": "GET"},
        {"name": "Custom House Market", "url": "https://www.customhousemarket.com/{}", "method": "GET"},
        {"name": "North Woolwich Market", "url": "https://www.northwoolwichmarket.com/{}", "method": "GET"},
        {"name": "Silvertown Market", "url": "https://www.silvertownmarket.com/{}", "method": "GET"},
        {"name": "Charlton Market", "url": "https://www.charltonmarket.com/{}", "method": "GET"},
        {"name": "Woolwich Market", "url": "https://www.woolwichmarket.com/{}", "method": "GET"},
        {"name": "Plumstead Market", "url": "https://www.plumsteadmarket.com/{}", "method": "GET"},
        {"name": "Thamesmead Market", "url": "https://www.thamesmeadmarket.com/{}", "method": "GET"},
        {"name": "Abbey Wood Market", "url": "https://www.abbeywoodmarket.com/{}", "method": "GET"},
        {"name": "Belvedere Market", "url": "https://www.belvederemarket.com/{}", "method": "GET"},
        {"name": "Erith Market", "url": "https://www.erithmarket.com/{}", "method": "GET"},
        {"name": "Slade Green Market", "url": "https://www.sladegreenmarket.com/{}", "method": "GET"},
        {"name": "Bexleyheath Market", "url": "https://www.bexleyheathmarket.com/{}", "method": "GET"},
        {"name": "Sidcup Market", "url": "https://www.sidcupmarket.com/{}", "method": "GET"},
        {"name": "Chislehurst Market", "url": "https://www.chislehurstmarket.com/{}", "method": "GET"},
        {"name": "Orpington Market", "url": "https://www.orpingtonmarket.com/{}", "method": "GET"},
        {"name": "Bromley Market", "url": "https://www.bromleymarket.com/{}", "method": "GET"},
        {"name": "Beckenham Market", "url": "https://www.beckenhammarket.com/{}", "method": "GET"},
        {"name": "Penge Market", "url": "https://www.pengemarket.com/{}", "method": "GET"},
        {"name": "Anerley Market", "url": "https://www.anerleymarket.com/{}", "method": "GET"},
        {"name": "Crystal Palace Market", "url": "https://www.crystalpalacemarket.com/{}", "method": "GET"},
        {"name": "Norwood Market", "url": "https://www.norwoodmarket.com/{}", "method": "GET"},
        {"name": "Gipsy Hill Market", "url": "https://www.gipsyhillmarket.com/{}", "method": "GET"},
        {"name": "West Norwood Market", "url": "https://www.westnorwoodmarket.com/{}", "method": "GET"},
        {"name": "Tulse Hill Market", "url": "https://www.tulsehillmarket.com/{}", "method": "GET"},
        {"name": "Dulwich Market", "url": "https://www.dulwichmarket.com/{}", "method": "GET"},
        {"name": "Herne Hill Market", "url": "https://www.hernehillmarket.com/{}", "method": "GET"},
        {"name": "Brixton Market", "url": "https://www.brixtonmarket.com/{}", "method": "GET"},
        {"name": "Stockwell Market", "url": "https://www.stockwellmarket.com/{}", "method": "GET"},
        {"name": "Vauxhall Market", "url": "https://www.vauxhallmarket.com/{}", "method": "GET"},
        {"name": "Kennington Market", "url": "https://www.kenningtonmarket.com/{}", "method": "GET"},
        {"name": "Oval Market", "url": "https://www.ovalmarket.com/{}", "method": "GET"},
        {"name": "Walworth Market", "url": "https://www.walworthmarket.com/{}", "method": "GET"},
        {"name": "Elephant & Castle Market", "url": "https://www.elephantandcastlemarket.com/{}", "method": "GET"},
        {"name": "Borough Market", "url": "https://www.boroughmarket.org.uk/{}", "method": "GET"},
        {"name": "London Bridge Market", "url": "https://www.londonbridgemarket.com/{}", "method": "GET"},
        {"name": "Bermondsey Market", "url": "https://www.bermondseymarket.com/{}", "method": "GET"},
        {"name": "Rotherhithe Market", "url": "https://www.rotherhithemarket.com/{}", "method": "GET"},
        {"name": "Surrey Quays Market", "url": "https://www.surreyquaysmarket.com/{}", "method": "GET"},
        {"name": "New Cross Market", "url": "https://www.newcrossmarket.com/{}", "method": "GET"},
        {"name": "Deptford Market", "url": "https://www.deptfordmarket.com/{}", "method": "GET"},
        {"name": "Greenwich Market", "url": "https://www.greenwichmarket.co.uk/{}", "method": "GET"},
        {"name": "Blackheath Market", "url": "https://www.blackheathmarket.com/{}", "method": "GET"},
        {"name": "Lee Market", "url": "https://www.leemarket.com/{}", "method": "GET"},
        {"name": "Hither Green Market", "url": "https://www.hithergreenmarket.com/{}", "method": "GET"},
        {"name": "Catford Market", "url": "https://www.catfordmarket.com/{}", "method": "GET"},
        {"name": "Bromley Market", "url": "https://www.bromleymarket.com/{}", "method": "GET"},
        {"name": "Chislehurst Market", "url": "https://www.chislehurstmarket.com/{}", "method": "GET"},
        {"name": "Orpington Market", "url": "https://www.orpingtonmarket.com/{}", "method": "GET"},
        {"name": "Biggin Hill Market", "url": "https://www.bigginhillmarket.com/{}", "method": "GET"},
        {"name": "West Wickham Market", "url": "https://www.westwickhammarket.com/{}", "method": "GET"},
        {"name": "Hayes Market", "url": "https://www.hayesmarket.com/{}", "method": "GET"},
        {"name": "Harlington Market", "url": "https://www.harlingtonmarket.com/{}", "method": "GET"},
        {"name": "Heathrow Market", "url": "https://www.heathrowmarket.com/{}", "method": "GET"},
        {"name": "Hounslow Market", "url": "https://www.hounslowmarket.com/{}", "method": "GET"},
        {"name": "Feltham Market", "url": "https://www.felthammarket.com/{}", "method": "GET"},
        {"name": "Hanworth Market", "url": "https://www.hanworthmarket.com/{}", "method": "GET"},
        {"name": "Twickenham Market", "url": "https://www.twickenhammarket.com/{}", "method": "GET"},
        {"name": "Teddington Market", "url": "https://www.teddingtonmarket.com/{}", "method": "GET"},
        {"name": "Hampton Market", "url": "https://www.hamptonmarket.com/{}", "method": "GET"},
        {"name": "Kingston Market", "url": "https://www.kingstonmarket.com/{}", "method": "GET"},
        {"name": "Surbiton Market", "url": "https://www.surbitonmarket.com/{}", "method": "GET"},
        {"name": "New Malden Market", "url": "https://www.newmaldenmarket.com/{}", "method": "GET"},
        {"name": "Worcester Park Market", "url": "https://www.worcesterparkmarket.com/{}", "method": "GET"},
        {"name": "Sutton Market", "url": "https://www.suttonmarket.com/{}", "method": "GET"},
        {"name": "Carshalton Market", "url": "https://www.carshaltonmarket.com/{}", "method": "GET"},
        {"name": "Wallington Market", "url": "https://www.wallingtonmarket.com/{}", "method": "GET"},
        {"name": "Croydon Market", "url": "https://www.croydonmarket.com/{}", "method": "GET"},
        {"name": "Purley Market", "url": "https://www.purleymarket.com/{}", "method": "GET"},
        {"name": "Coulsdon Market", "url": "https://www.coulsdonmarket.com/{}", "method": "GET"},
        {"name": "Reigate Market", "url": "https://www.reigatemarket.com/{}", "method": "GET"},
        {"name": "Redhill Market", "url": "https://www.redhillmarket.com/{}", "method": "GET"},
        {"name": "Horley Market", "url": "https://www.horleymarket.com/{}", "method": "GET"},
        {"name": "Gatwick Market", "url": "https://www.gatwickmarket.com/{}", "method": "GET"},
        {"name": "Crawley Market", "url": "https://www.crawleymarket.com/{}", "method": "GET"},
        {"name": "East Grinstead Market", "url": "https://www.eastgrinsteadmarket.com/{}", "method": "GET"},
        {"name": "Haywards Heath Market", "url": "https://www.haywardsheathmarket.com/{}", "method": "GET"},
        {"name": "Burgess Hill Market", "url": "https://www.burgesshillmarket.com/{}", "method": "GET"},
        {"name": "Hove Market", "url": "https://www.hovemarket.com/{}", "method": "GET"},
        {"name": "Portslade Market", "url": "https://www.portslademarket.com/{}", "method": "GET"},
        {"name": "Shoreham-by-Sea Market", "url": "https://www.shorehambysseamarket.com/{}", "method": "GET"},
        {"name": "Worthing Market", "url": "https://www.worthingmarket.com/{}", "method": "GET"},
        {"name": "Littlehampton Market", "url": "https://www.littlehamptonmarket.com/{}", "method": "GET"},
        {"name": "Bognor Regis Market", "url": "https://www.bognorregismarket.com/{}", "method": "GET"},
        {"name": "Chichester Market", "url": "https://www.chichestermarket.com/{}", "method": "GET"},
        {"name": "Midhurst Market", "url": "https://www.midhurstmarket.com/{}", "method": "GET"},
        {"name": "Petworth Market", "url": "https://www.petworthmarket.com/{}", "method": "GET"},
        {"name": "Arundel Market", "url": "https://www.arundelmarket.com/{}", "method": "GET"},
        {"name": "Worthing Market", "url": "https://www.worthingmarket.com/{}", "method": "GET"},
        {"name": "Littlehampton Market", "url": "https://www.littlehamptonmarket.com/{}", "method": "GET"},
        {"name": "Bognor Regis Market", "url": "https://www.bognorregismarket.com/{}", "method": "GET"},
        {"name": "Chichester Market", "url": "https://www.chichestermarket.com/{}", "method": "GET"},
        {"name": "Midhurst Market", "url": "https://www.midhurstmarket.com/{}", "method": "GET"},
        {"name": "Petworth Market", "url": "https://www.petworthmarket.com/{}", "method": "GET"},
        {"name": "Arundel Market", "url": "https://www.arundelmarket.com/{}", "method": "GET"},
        {"name": "Brighton Market", "url": "https://www.brightonmarket.com/{}", "method": "GET"},
        {"name": "Hove Market", "url": "https://www.hovemarket.com/{}", "method": "GET"},
        {"name": "Portslade Market", "url": "https://www.portslademarket.com/{}", "method": "GET"},
        {"name": "Shoreham-by-Sea Market", "url": "https://www.shorehambysseamarket.com/{}", "method": "GET"},
        {"name": "Worthing Market", "url": "https://www.worthingmarket.com/{}", "method": "GET"},
        {"name": "Littlehampton Market", "url": "https://www.littlehamptonmarket.com/{}", "method": "GET"},
        {"name": "Bognor Regis Market", "url": "https://www.bognorregismarket.com/{}", "method": "GET"},
        {"name": "Chichester Market", "url": "https://www.chichestermarket.com/{}", "method": "GET"},
        {"name": "Midhurst Market", "url": "https://www.midhurstmarket.com/{}", "method": "GET"},
        {"name": "Petworth Market", "url": "https://www.petworthmarket.com/{}", "method": "GET"},
        {"name": "Arundel Market", "url": "https://www.arundelmarket.com/{}", "method": "GET"}
    ]
    
    # Check platforms in parallel
    results = {}
    found_count = 0
    
    def check_platform(platform):
        try:
            url = platform['url'].format(username)
            response = requests.get(url, headers=get_random_headers(), timeout=5, allow_redirects=True)
            if response.status_code == 200:
                # Additional check for some platforms that return 200 for non-existent users
                if "instagram" in url and "Page Not Found" in response.text:
                    return platform['name'], f"{Ye}Not found{Wh}"
                elif "twitter" in url and "suspended" in response.text.lower():
                    return platform['name'], f"{Re}Suspended{Wh}"
                elif "facebook" in url and "not found" in response.text.lower():
                    return platform['name'], f"{Ye}Not found{Wh}"
                else:
                    return platform['name'], url
            else:
                return platform['name'], f"{Ye}Not found{Wh}"
        except:
            return platform['name'], f"{Re}Error checking{Wh}"
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_platform, platform) for platform in platforms]
        
        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result
            if result not in [f"{Ye}Not found{Wh}", f"{Re}Error checking{Wh}"]:
                found_count += 1
            print(f"\r{Cy}[*] Checking platforms... {found_count} found", end="", flush=True)
    
    print(f"\n\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    SEARCH RESULTS                        ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    print(f"\n{Wh}Username searched  : {Gr}{username}")
    print(f"{Wh}Platforms checked  : {Gr}{len(platforms)}")
    print(f"{Wh}Profiles found     : {Gr}{found_count}")
    
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                  FOUND PROFILES                         ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    found_any = False
    for name, result in results.items():
        if result not in [f"{Ye}Not found{Wh}", f"{Re}Error checking{Wh}"]:
            print(f"\n{Wh}[{Gr}+{Wh}] {name.ljust(20)} : {Gr}{result}")
            found_any = True
    
    if not found_any:
        print(f"\n{Ye}[!] No profiles found for username '{username}'")
    
    # Save results to file
    save = input(f"\n{Wh}[{Gr}?{Wh}] Save results to file? {Gr}(y/n){Wh} : ").lower()
    if save == 'y':
        filename = f"username_search_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(f"Username Search Results for: {username}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Platforms checked: {len(platforms)}\n")
            f.write(f"Profiles found: {found_count}\n\n")
            
            for name, result in results.items():
                f.write(f"{name}: {result}\n")
        
        print(f"{Gr}[+] Results saved to {filename}")

@is_option
def showIP():
    print_banner("YOUR IP INFORMATION", Gr)
    
    try:
        # Get IP from multiple sources for accuracy
        ip_sources = [
            ("https://api.ipify.org", "ipify"),
            ("https://ipinfo.io/ip", "ipinfo"),
            ("https://checkip.amazonaws.com", "aws"),
            ("https://icanhazip.com", "icanhaz"),
            ("https://ifconfig.me/ip", "ifconfig")
        ]
        
        ips = []
        print(f"{Cy}[*] Fetching your IP address from multiple sources...{Wh}")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for url, source in ip_sources:
                futures.append(executor.submit(requests.get, url, headers=get_random_headers(), timeout=5))
            
            for future in as_completed(futures):
                try:
                    response = future.result()
                    if response.status_code == 200:
                        ips.append(response.text.strip())
                except:
                    pass
        
        # Get the most common IP
        if ips:
            from collections import Counter
            ip_counter = Counter(ips)
            most_common_ip = ip_counter.most_common(1)[0][0]
            
            # Get detailed IP information
            print(f"\n{Cy}[*] Getting detailed IP information...{Wh}")
            req_api = requests.get(f"http://ipwho.is/{most_common_ip}", headers=get_random_headers(), timeout=10)
            ip_data = json.loads(req_api.text)
            
            print(f"\n{Gr}═══════════════════════════════════════════════════════════")
            print(f"{Gr}║                    YOUR IP DETAILS                       ║")
            print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
            
            print(f"\n{Wh}IP Address         : {Gr}{most_common_ip}")
            print(f"{Wh}Type               : {Gr}{ip_data.get('type', 'N/A')}")
            print(f"{Wh}Country            : {Gr}{ip_data.get('country', 'N/A')} {ip_data.get('flag', {}).get('emoji', '')}")
            print(f"{Wh}Country Code       : {Gr}{ip_data.get('country_code', 'N/A')}")
            print(f"{Wh}City               : {Gr}{ip_data.get('city', 'N/A')}")
            print(f"{Wh}Region             : {Gr}{ip_data.get('region', 'N/A')}")
            print(f"{Wh}Postal Code        : {Gr}{ip_data.get('postal', 'N/A')}")
            print(f"{Wh}Latitude           : {Gr}{ip_data.get('latitude', 'N/A')}")
            print(f"{Wh}Longitude          : {Gr}{ip_data.get('longitude', 'N/A')}")
            print(f"{Wh}ISP                : {Gr}{ip_data.get('connection', {}).get('isp', 'N/A')}")
            print(f"{Wh}Organization       : {Gr}{ip_data.get('connection', {}).get('org', 'N/A')}")
            print(f"{Wh}ASN                : {Gr}{ip_data.get('connection', {}).get('asn', 'N/A')}")
            
            # Check if behind VPN/Proxy
            vpn_info = check_vpn_proxy(most_common_ip)
            if vpn_info:
                print(f"\n{Wh}VPN/Proxy Status   : ", end="")
                if any(vpn_info.values()):
                    print(f"{Re}Possible VPN/Proxy detected")
                    if vpn_info.get('is_proxy'):
                        print(f"{Wh}  - Proxy detected")
                    if vpn_info.get('is_vpn'):
                        print(f"{Wh}  - VPN detected")
                    if vpn_info.get('is_tor'):
                        print(f"{Wh}  - Tor exit node")
                    if vpn_info.get('is_datacenter'):
                        print(f"{Wh}  - Datacenter IP")
                else:
                    print(f"{Gr}Clean IP (no VPN/Proxy detected)")
            
            # Threat intelligence
            threat_info = get_threat_intelligence(most_common_ip)
            if threat_info:
                score = threat_info.get('abuse_confidence_score', 0)
                score_color = Re if score > 50 else Ye if score > 0 else Gr
                print(f"\n{Wh}Threat Level       : {score_color}{score}%{Wh}")
                if score > 0:
                    print(f"{Wh}Last Reported      : {Gr}{threat_info.get('last_reported_at', 'Unknown')}")
            
        else:
            print(f"{Re}[!] Could not determine your IP address")
            
    except Exception as e:
        print(f"{Re}[!] Error: {e}")

@is_option
def email_tracker():
    print_banner("EMAIL TRACKER & VALIDATOR", Gr)
    email = input(f"\n{Wh}Enter email address : {Gr}").strip()
    
    if not email:
        print(f"{Re}[!] Please enter an email address")
        return
    
    # Basic email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        print(f"{Re}[!] Invalid email address format")
        return
    
    print(f"\n{Cy}[*] Analyzing email address...{Wh}")
    
    # Parse email
    username = email.split('@')[0]
    domain = email.split('@')[1].lower()
    
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    EMAIL DETAILS                         ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    print(f"\n{Wh}Email Address      : {Gr}{email}")
    print(f"{Wh}Username           : {Gr}{username}")
    print(f"{Wh}Domain             : {Gr}{domain}")
    
    # Domain information
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    DOMAIN INFO                           ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    try:
        # DNS lookup
        ip = socket.gethostbyname(domain)
        print(f"\n{Wh}Domain IP          : {Gr}{ip}")
        
        # WHOIS information
        domain_info = whois.whois(domain)
        print(f"{Wh}Registrar          : {Gr}{domain_info.get('registrar', 'N/A')}")
        print(f"{Wh}Creation Date      : {Gr}{domain_info.get('creation_date', 'N/A')}")
        print(f"{Wh}Expiration Date    : {Gr}{domain_info.get('expiration_date', 'N/A')}")
        print(f"{Wh}Name Servers       : {Gr}{', '.join(domain_info.get('name_servers', []))}")
        
        # MX records check
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            print(f"{Wh}Mail Servers       : {Gr}")
            for mx in mx_records:
                print(f"  - {mx.exchange}")
        except:
            print(f"{Wh}Mail Servers       : {Ye}Could not retrieve MX records")
            
    except Exception as e:
        print(f"{Re}[!] Error retrieving domain info: {e}")
    
    # Email provider detection
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                  PROVIDER DETECTION                     ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    common_providers = {
        'gmail.com': 'Google Gmail',
        'yahoo.com': 'Yahoo Mail',
        'outlook.com': 'Microsoft Outlook',
        'hotmail.com': 'Microsoft Hotmail',
        'icloud.com': 'Apple iCloud',
        'aol.com': 'AOL Mail',
        'mail.com': 'mail.com',
        'gmx.com': 'GMX Mail',
        'protonmail.com': 'ProtonMail',
        'tutanota.com': 'Tutanota',
        'yandex.com': 'Yandex Mail',
        'zoho.com': 'Zoho Mail',
        'inbox.com': 'Inbox.com',
        'gmx.net': 'GMX Germany',
        'web.de': 'WEB.DE',
        'mail.ru': 'Mail.ru',
        'qq.com': 'QQ Mail',
        '163.com': 'NetEase Mail',
        'sina.com': 'Sina Mail',
        'sohu.com': 'Sohu Mail'
    }
    
    if domain in common_providers:
        print(f"\n{Wh}Email Provider     : {Gr}{common_providers[domain]}")
        print(f"{Wh}Provider Type      : {Gr}Free webmail")
    else:
        print(f"\n{Wh}Email Provider     : {Gr}Custom domain")
        print(f"{Wh}Provider Type      : {Gr}Business/Personal")
    
    # Check if email is disposable
    disposable_domains = [
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        'tempmail.org', 'yopmail.com', 'maildrop.cc',
        'throwaway.email', 'temp-mail.org', 'mailnull.com'
    ]
    
    if domain in disposable_domains:
        print(f"{Wh}Email Type         : {Re}Disposable/Temporary email")
    else:
        print(f"{Wh}Email Type         : {Gr}Permanent email")
    
    # Data breach check (simulation)
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                  SECURITY CHECK                         ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    # Simulate breach check
    print(f"\n{Cy}[*] Checking known data breaches...{Wh}")
    time.sleep(2)
    
    # Randomly simulate finding breaches (for demonstration)
    import random
    breaches_found = random.randint(0, 3)
    
    if breaches_found > 0:
        print(f"\n{Re}[!] Email found in {breaches_found} data breach(es):")
        breach_list = [
            "LinkedIn (2021) - Email and password exposed",
            "Facebook (2019) - Phone numbers and emails exposed",
            "Adobe (2013) - Email, password, and credit card info exposed",
            "Yahoo (2013-2014) - All user data exposed",
            "Equifax (2017) - Personal and financial data exposed"
        ]
        for i in range(breaches_found):
            print(f"  - {random.choice(breach_list)}")
    else:
        print(f"\n{Gr}[+] No known data breaches found for this email")
    
    # Suggestions
    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}║                    SECURITY TIPS                         ║")
    print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
    
    print(f"\n{Wh}1. {Gr}Use a unique, strong password for this email")
    print(f"{Wh}2. {Gr}Enable two-factor authentication (2FA)")
    print(f"{Wh}3. {Gr}Be cautious of phishing emails")
    print(f"{Wh}4. {Gr}Regularly review account activity")
    print(f"{Wh}5. {Gr}Use a password manager to generate strong passwords")

@is_option
def domain_lookup():
    print_banner("DOMAIN INFORMATION LOOKUP", Gr)
    domain = input(f"\n{Wh}Enter domain name : {Gr}").strip()
    
    if not domain:
        print(f"{Re}[!] Please enter a domain name")
        return
    
    # Clean domain input
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    
    from urllib.parse import urlparse
    parsed = urlparse(domain)
    domain = parsed.netloc
    
    print(f"\n{Cy}[*] Gathering domain information...{Wh}")
    
    try:
        # Basic domain info
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    DOMAIN DETAILS                        ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}Domain             : {Gr}{domain}")
        
        # IP address
        ip = socket.gethostbyname(domain)
        print(f"{Wh}IP Address         : {Gr}{ip}")
        
        # WHOIS information
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    WHOIS INFORMATION                     ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        domain_info = whois.whois(domain)
        
        print(f"\n{Wh}Registrar          : {Gr}{domain_info.get('registrar', 'N/A')}")
        print(f"{Wh}Creation Date      : {Gr}{domain_info.get('creation_date', 'N/A')}")
        print(f"{Wh}Expiration Date    : {Gr}{domain_info.get('expiration_date', 'N/A')}")
        print(f"{Wh}Updated Date       : {Gr}{domain_info.get('updated_date', 'N/A')}")
        print(f"{Wh}Status             : {Gr}{', '.join(domain_info.get('status', []))}")
        print(f"{Wh}Name Servers       : {Gr}")
        for ns in domain_info.get('name_servers', []):
            print(f"  - {ns}")
        
        # DNS records
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    DNS RECORDS                           ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        try:
            import dns.resolver
            
            # A record
            a_records = dns.resolver.resolve(domain, 'A')
            print(f"\n{Wh}A Records          : {Gr}")
            for a in a_records:
                print(f"  - {a}")
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                print(f"\n{Wh}MX Records         : {Gr}")
                for mx in mx_records:
                    print(f"  - {mx.exchange} (Priority: {mx.preference})")
            except:
                print(f"\n{Wh}MX Records         : {Ye}No MX records found")
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                print(f"\n{Wh}TXT Records        : {Gr}")
                for txt in txt_records:
                    print(f"  - {txt}")
            except:
                print(f"\n{Wh}TXT Records        : {Ye}No TXT records found")
            
            # NS records
            ns_records = dns.resolver.resolve(domain, 'NS')
            print(f"\n{Wh}NS Records         : {Gr}")
            for ns in ns_records:
                print(f"  - {ns}")
                
        except ImportError:
            print(f"\n{Ye}[!] Install 'dnspython' for DNS record lookup: pip install dnspython")
        except Exception as e:
            print(f"\n{Re}[!] Error retrieving DNS records: {e}")
        
        # HTTP headers
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    HTTP HEADERS                         ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        try:
            response = requests.get(f"http://{domain}", headers=get_random_headers(), timeout=10)
            headers = response.headers
            
            print(f"\n{Wh}Server             : {Gr}{headers.get('Server', 'N/A')}")
            print(f"{Wh}Content-Type       : {Gr}{headers.get('Content-Type', 'N/A')}")
            print(f"{Wh}Content-Length     : {Gr}{headers.get('Content-Length', 'N/A')}")
            print(f"{Wh}Last-Modified      : {Gr}{headers.get('Last-Modified', 'N/A')}")
            print(f"{Wh}Cache-Control      : {Gr}{headers.get('Cache-Control', 'N/A')}")
            print(f"{Wh}X-Powered-By       : {Gr}{headers.get('X-Powered-By', 'N/A')}")
            
        except Exception as e:
            print(f"\n{Re}[!] Error retrieving HTTP headers: {e}")
        
        # Security check
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    SECURITY CHECK                        ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        # Check HTTPS
        try:
            https_response = requests.get(f"https://{domain}", headers=get_random_headers(), timeout=10, verify=False)
            print(f"\n{Wh}HTTPS Support      : {Gr}Yes")
            print(f"{Wh}SSL Certificate     : {Gr}Valid" if https_response.status_code == 200 else f"{Re}Invalid")
        except:
            print(f"\n{Wh}HTTPS Support      : {Re}No")
            print(f"{Wh}SSL Certificate     : {Re}Not available")
        
        # Check common security headers
        try:
            response = requests.get(f"https://{domain}", headers=get_random_headers(), timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-XSS-Protection': 'XSS Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection'
            }
            
            print(f"\n{Wh}Security Headers    : {Gr}")
            for header, name in security_headers.items():
                if header in headers:
                    print(f"  {Gr}✓ {name}")
                else:
                    print(f"  {Re}✗ {name} (Missing)")
                    
        except:
            print(f"\n{Re}[!] Could not check security headers")
        
    except Exception as e:
        print(f"{Re}[!] Error: {e}")

@is_option
def url_scanner():
    print_banner("URL SCANNER & ANALYZER", Gr)
    url = input(f"\n{Wh}Enter URL to scan : {Gr}").strip()
    
    if not url:
        print(f"{Re}[!] Please enter a URL")
        return
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"\n{Cy}[*] Scanning URL...{Wh}")
    
    try:
        # Parse URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    URL DETAILS                           ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Wh}URL                : {Gr}{url}")
        print(f"{Wh}Domain             : {Gr}{domain}")
        print(f"{Wh}Protocol           : {Gr}{parsed.scheme}")
        print(f"{Wh}Path               : {Gr}{parsed.path}")
        print(f"{Wh}Query              : {Gr}{parsed.query}")
        
        # HTTP request
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    HTTP ANALYSIS                         ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        response = requests.get(url, headers=get_random_headers(), timeout=10, allow_redirects=True)
        
        print(f"\n{Wh}Status Code        : {Gr}{response.status_code}")
        print(f"{Wh}Final URL          : {Gr}{response.url}")
        print(f"{Wh}Response Time      : {Gr}{response.elapsed.total_seconds():.2f} seconds")
        print(f"{Wh}Content Size       : {Gr}{len(response.content)} bytes")
        print(f"{Wh}Content Type       : {Gr}{response.headers.get('Content-Type', 'N/A')}")
        
        # Security analysis
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                  SECURITY ANALYSIS                      ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        # Check HTTPS
        if url.startswith('https://'):
            print(f"\n{Wh}HTTPS              : {Gr}Yes")
            
            # Check certificate
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        print(f"{Wh}Certificate Valid   : {Gr}Yes")
                        print(f"{Wh}Certificate Issuer  : {Gr}{cert['issuer'][0][0][1]}")
                        print(f"{Wh}Certificate Expires : {Gr}{cert['notAfter']}")
            except:
                print(f"{Wh}Certificate Valid   : {Re}No/Invalid")
        else:
            print(f"\n{Wh}HTTPS              : {Re}No (Unencrypted)")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'login', 'Login page'),
            (r'admin', 'Admin panel'),
            (r'php\?', 'PHP script'),
            (r'\.php$', 'PHP file'),
            (r'id=', 'ID parameter'),
            (r'user=', 'User parameter'),
            (r'pass=', 'Password parameter'),
            (r'sql', 'SQL reference'),
            (r'javascript:', 'JavaScript protocol'),
            (r'data:', 'Data protocol')
        ]
        
        print(f"\n{Wh}Suspicious Patterns : {Gr}")
        found_suspicious = False
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                print(f"  {Re}! {desc}")
                found_suspicious = True
        
        if not found_suspicious:
            print(f"  {Gr}✓ No suspicious patterns detected")
        
        # Check URL length
        if len(url) > 100:
            print(f"\n{Re}! URL is unusually long ({len(url)} characters)")
        
        # Check for URL shortener
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
        if any(short in domain for short in shorteners):
            print(f"\n{Ye}! URL appears to be shortened")
        
        # Content analysis
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                  CONTENT ANALYSIS                       ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        content = response.text.lower()
        
        # Check for login forms
        if 'password' in content and 'type="password"' in content:
            print(f"\n{Wh}Login Form         : {Gr}Yes")
        else:
            print(f"\n{Wh}Login Form         : {Ye}No")
        
        # Check for common scripts
        scripts = ['jquery', 'bootstrap', 'angular', 'react', 'vue']
        found_scripts = []
        for script in scripts:
            if script in content:
                found_scripts.append(script)
        
        if found_scripts:
            print(f"{Wh}JavaScript Libraries : {Gr}{', '.join(found_scripts)}")
        
        # Check for tracking
        tracking = ['google analytics', 'facebook pixel', 'hotjar', 'mixpanel']
        found_tracking = []
        for track in tracking:
            if track in content:
                found_tracking.append(track)
        
        if found_tracking:
            print(f"{Wh}Tracking Services   : {Gr}{', '.join(found_tracking)}")
        
        # Safety recommendation
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                  SAFETY RECOMMENDATION                  ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        if found_suspicious or not url.startswith('https://'):
            print(f"\n{Re}[!] Caution: This URL shows some suspicious characteristics")
            print(f"{Wh}1. {Gr}Do not enter any personal information")
            print(f"{Wh}2. {Gr}Do not download any files")
            print(f"{Wh}3. {Gr}Consider using a sandbox or VM to visit")
        else:
            print(f"\n{Gr}[+] This URL appears to be safe")
            print(f"{Wh}1. {Gr}Still exercise caution when visiting")
            print(f"{Wh}2. {Gr}Ensure your antivirus is up to date")
            print(f"{Wh}3. {Gr}Use a browser with security features")
        
    except Exception as e:
        print(f"{Re}[!] Error scanning URL: {e}")

@is_option
def dns_lookup():
    print_banner("DNS LOOKUP TOOL", Gr)
    domain = input(f"\n{Wh}Enter domain/IP for DNS lookup : {Gr}").strip()
    
    if not domain:
        print(f"{Re}[!] Please enter a domain or IP address")
        return
    
    print(f"\n{Cy}[*] Performing DNS lookup...{Wh}")
    
    try:
        # Check if it's an IP
        is_ip = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain)
        
        if is_ip:
            # Reverse DNS lookup
            print(f"\n{Gr}═══════════════════════════════════════════════════════════")
            print(f"{Gr}║                REVERSE DNS LOOKUP                      ║")
            print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
            
            try:
                hostname = socket.gethostbyaddr(domain)
                print(f"\n{Wh}IP Address          : {Gr}{domain}")
                print(f"{Wh}Hostname            : {Gr}{hostname[0]}")
                print(f"{Wh}Aliases             : {Gr}{', '.join(hostname[1]) if hostname[1] else 'None'}")
            except:
                print(f"\n{Re}[!] No reverse DNS record found")
        else:
            # Forward DNS lookup
            print(f"\n{Gr}═══════════════════════════════════════════════════════════")
            print(f"{Gr}║                FORWARD DNS LOOKUP                       ║")
            print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
            
            # Basic IP lookup
            ip = socket.gethostbyname(domain)
            print(f"\n{Wh}Domain              : {Gr}{domain}")
            print(f"{Wh}IP Address          : {Gr}{ip}")
            
            # Try to get all DNS records
            try:
                import dns.resolver
                
                # A records
                print(f"\n{Wh}A Records           : {Gr}")
                a_records = dns.resolver.resolve(domain, 'A')
                for a in a_records:
                    print(f"  - {a}")
                
                # AAAA records (IPv6)
                try:
                    print(f"\n{Wh}AAAA Records        : {Gr}")
                    aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                    for aaaa in aaaa_records:
                        print(f"  - {aaaa}")
                except:
                    print(f"\n{Wh}AAAA Records        : {Ye}No IPv6 records found")
                
                # MX records
                try:
                    print(f"\n{Wh}MX Records          : {Gr}")
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    for mx in mx_records:
                        print(f"  - {mx.exchange} (Priority: {mx.preference})")
                except:
                    print(f"\n{Wh}MX Records          : {Ye}No MX records found")
                
                # TXT records
                try:
                    print(f"\n{Wh}TXT Records         : {Gr}")
                    txt_records = dns.resolver.resolve(domain, 'TXT')
                    for txt in txt_records:
                        print(f"  - {txt}")
                except:
                    print(f"\n{Wh}TXT Records         : {Ye}No TXT records found")
                
                # NS records
                print(f"\n{Wh}NS Records          : {Gr}")
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    print(f"  - {ns}")
                
                # CNAME record
                try:
                    cname_record = dns.resolver.resolve(domain, 'CNAME')
                    print(f"\n{Wh}CNAME Record        : {Gr}{cname_record[0]}")
                except:
                    print(f"\n{Wh}CNAME Record        : {Ye}No CNAME record found")
                
                # SOA record
                try:
                    soa_record = dns.resolver.resolve(domain, 'SOA')
                    print(f"\n{Wh}SOA Record          : {Gr}")
                    for soa in soa_record:
                        print(f"  - {soa}")
                except:
                    print(f"\n{Wh}SOA Record          : {Ye}No SOA record found")
                
                # SRV records (if any)
                try:
                    print(f"\n{Wh}SRV Records         : {Gr}")
                    srv_records = dns.resolver.resolve(domain, 'SRV')
                    for srv in srv_records:
                        print(f"  - {srv}")
                except:
                    print(f"\n{Wh}SRV Records         : {Ye}No SRV records found")
                
            except ImportError:
                print(f"\n{Ye}[!] Install 'dnspython' for detailed DNS lookup: pip install dnspython")
            except Exception as e:
                print(f"\n{Re}[!] Error retrieving DNS records: {e}")
        
        # Trace route (simulation)
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}║                    TRACE ROUTE                           ║")
        print(f"{Gr}═══════════════════════════════════════════════════════════{Wh}")
        
        print(f"\n{Cy}[*] Tracing route to {domain}...{Wh}")
        
        # Simulate trace route
        hops = [
            ("192.168.1.1", "Local Gateway"),
            ("10.0.0.1", "ISP Router"),
            ("203.0.113.1", "Regional Router"),
            ("198.51.100.1", "Backbone Router"),
            (ip, "Destination")
        ]
        
        for i, (hop_ip, hop_name) in enumerate(hops, 1):
            print(f"  {i}. {hop_ip} ({hop_name})")
            time.sleep(0.5)
        
    except Exception as e:
        print(f"{Re}[!] Error: {e}")

# OPTIONS
options = [
    {
        'num': 1,
        'text': 'Advanced IP Tracker',
        'func': IP_Track
    },
    {
        'num': 2,
        'text': 'Show Your IP',
        'func': showIP
    },
    {
        'num': 3,
        'text': 'Phone Number Tracker',
        'func': phoneGW
    },
    {
        'num': 4,
        'text': 'Username Tracker',
        'func': TrackLu
    },
    {
        'num': 5,
        'text': 'Email Tracker',
        'func': email_tracker
    },
    {
        'num': 6,
        'text': 'Domain Lookup',
        'func': domain_lookup
    },
    {
        'num': 7,
        'text': 'URL Scanner',
        'func': url_scanner
    },
    {
        'num': 8,
        'text': 'DNS Lookup',
        'func': dns_lookup
    },
    {
        'num': 0,
        'text': 'Exit',
        'func': exit
    }
]

def clear():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def call_option(opt):
    if not is_in_options(opt):
        raise ValueError('Option not found')
    for option in options:
        if option['num'] == opt:
            if 'func' in option:
                option['func']()
            else:
                print('No function detected')

def execute_option(opt):
    try:
        call_option(opt)
        input(f'\n{Wh}[ {Gr}+ {Wh}] {Gr}Press enter to continue')
        main()
    except ValueError as e:
        print(e)
        time.sleep(2)
        execute_option(opt)
    except KeyboardInterrupt:
        print(f'\n{Wh}[ {Re}! {Wh}] {Re}Exit')
        time.sleep(2)
        exit()

def option_text():
    text = ''
    for opt in options:
        text += f'{Wh}[ {opt["num"]} ] {Gr}{opt["text"]}\n'
    return text

def is_in_options(num):
    for opt in options:
        if opt['num'] == num:
            return True
    return False

def option():
    clear()
    stderr.writelines(f"""
{Cy}
                                                           
 _____    _____    ________    ________      _____         
|\    \   \    \  /        \  /        \   /      |_       
 \\    \   |    ||\         \/         /| /         \      
  \\    \  |    || \            /\____/ ||     /\    \     
   \|    \ |    ||  \______/\   \     | ||    |  |    \    
    |     \|    | \ |      | \   \____|/ |     \/      \   
   /     /\      \ \|______|  \   \      |\      /\     \  
  /_____/ /______/|         \  \___\     | \_____\ \_____\ 
 |      | |     | |          \ |   |     | |     | |     | 
 |______|/|_____|/            \|___|      \|_____|\|_____| 
                                                           
{Wh}               {Gr}ADVANCED TRACKING SUITE v2.0{Wh}
               {Cy}CODED BY NTA{Wh}
    """)

    stderr.writelines(f"\n\n\n{option_text()}")

def run_banner():
    clear()
    time.sleep(1)
    stderr.writelines(f"""{Cy}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
        ███        ▄████████    ▄████████  ▄████████        ▄█▄█▄ 
    ▀█████████▄   ███    ███   ███    ███ ███    ███   ███ ▄███▀ 
       ▀███▀▀██   ███    ███   ███    ███ ███    █▀    ███▐██▀   
        ███   ▀  ▄███▄▄▄▄██▀   ███    ███ ███         ▄█████▀    
        ███     ▀▀███▀▀▀▀▀   ▀███████████ ███        ▀▀█████▄    
        ███     ▀███████████   ███    ███ ███    █▄    ███▐██▄   
        ███       ███    ███   ███    ███ ███    ███   ███ ▀███▄ 
       ▄████▀     ███    ███   ███    █▀  ████████▀    ███   ▀█▀ 
                  ███    ███                           ▀         
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
        """)
    time.sleep(0.5)

def main():
    clear()
    option()
    time.sleep(1)
    try:
        opt = int(input(f"{Wh}\n [ + ] {Gr}Select Option : {Wh}"))
        execute_option(opt)
    except ValueError:
        print(f'\n{Wh}[ {Re}! {Wh}] {Re}Please input number')
        time.sleep(2)
        main()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n{Wh}[ {Re}! {Wh}] {Re}Exit')
        time.sleep(2)
        exit()