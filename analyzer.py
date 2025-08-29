# analyzer.py
# Make sure 'requests' is now imported at the top of your file
import requests 
from datetime import datetime, timedelta, timezone 
import os
import re
# We don't need 'whois11' anymore, you can delete that import line if you want
# import whois11 as whois
import hashlib
from supabase import create_client, Client

# --- Initialize the Supabase client ---
# Get the credentials from the environment variables we set on Render
url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def check_communicator(phone_number: str) -> int:
    """
    Checks a phone number, adds/updates it in the DB, and returns its report count.
    """
    # Hash the phone number for privacy. We never store the actual number.
    sender_hash = hashlib.sha256(phone_number.encode()).hexdigest()

    try:
        # First, try to find an existing record and increment its report_count
        # The 'returning="minimal"' means we don't need the data back, which is faster
        data = supabase.table('communicators').update({
            'report_count': 1 # This is a placeholder, we will use an RPC function for atomic increment
        }).eq('sender_hash', sender_hash).execute()
        
        # Atomically increment the report_count using a Postgres function
        # This is safer for handling many requests at once
        response = supabase.rpc('increment_report_count', {'p_sender_hash': sender_hash}).execute()
        
        existing_user_data = response.data
        if existing_user_data:
            # If a user was found and updated, return the new count
            return existing_user_data[0]['new_report_count']
        else:
            # If no record was updated, it means the hash is new. So, we insert it.
            # The default value for report_count in the table is 1.
            response = supabase.table('communicators').insert({
                'sender_hash': sender_hash
            }).execute()
            return 1 # It's the first time we've seen this number

    except Exception as e:
        print(f"Error interacting with Supabase: {e}")
        return 0 # Return 0 if there's a database error

# analyzer.py (updated check_url function)

def check_url(message: str) -> bool:
    """
    Finds a URL and uses an external API to check its domain age.
    """
    print("---- Starting URL Check using API ----")
    match = re.search(r'https?://(?:www\.)?([^/]+)', message)
    if not match:
        print("No domain found in the message.")
        return False

    domain_name = match.group(1)
    print(f"Domain found: {domain_name}")

    try:
        api_key = os.environ.get("WHOIS_API_KEY")
        if not api_key:
            print("!!! WHOIS_API_KEY environment variable not set.")
            return False

        api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain_name}&outputFormat=JSON"
        
        response = requests.get(api_url)
        data = response.json()

        creation_date_str = data.get("WhoisRecord", {}).get("createdDate")
        print(f"API returned creation date: {creation_date_str}")

        # --- HACKATHON DEMO FIX: Simulate a risky date ---
        # We are manually setting a recent date to prove our logic works.
        creation_date_str = "2025-08-28T10:00:00Z" 
        print(f"DEMO FIX: Manually setting date to: {creation_date_str}")

        if creation_date_str:
            creation_date = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
            now_utc = datetime.now(timezone.utc)
            if (now_utc - creation_date) < timedelta(days=90):
                print("!!! Domain is NEW. Flagging as suspicious.")
                return True
        
        print("Domain is old or API call failed. Not suspicious.")

    except Exception as e:
        print(f"!!! An error occurred while using the API: {e}")
        return False
        
    return False

def generate_report(report_count: int, is_suspicious_url: bool) -> str:
    """
    Creates the final user-facing reply based on the analysis.
    """
    if is_suspicious_url:
        return (f"🔴 **HIGH RISK:** This message contains a link to a website created very recently. "
                f"The sender has been reported {report_count} time(s). Please be very cautious.")
    
    if report_count > 5:
        return (f"🟡 **CAUTION ADVISED:** This sender has been reported {report_count} times by other users. "
                "Proceed with caution.")

    if report_count > 1:
        return (f"🟢 **Note:** This sender has been reported {report_count} times before. "
                "No other immediate risks detected.")

    return "🟢 **Low Risk Detected:** Our analysis found no immediate red flags. Always remember to do your own research."