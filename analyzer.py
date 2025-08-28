# analyzer.py
import os
import re
import whois
import hashlib
from datetime import datetime, timedelta
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
        }).eq('sender_hash', sender_hash).execute(returning="minimal")
        
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

def check_url(message: str) -> bool:
    """
    Finds the first URL in a message and checks if its domain is new.
    Returns True if suspicious (new), False otherwise.
    """
    # Use regular expressions to find the first http or https URL in the message
    match = re.search(r'https?://[^\s]+', message)
    if not match:
        return False # No URL found

    url = match.group(0)
    try:
        # Get domain information
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date

        # Sometimes creation_date is a list, so we handle that
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Check if the domain was created in the last 90 days
        if creation_date and (datetime.now() - creation_date) < timedelta(days=90):
            print(f"Suspicious URL found: {url} (created recently)")
            return True # Domain is new, so it's suspicious
            
    except Exception as e:
        print(f"Could not check URL {url}: {e}")
        # If we can't check the URL, we'll assume it's not suspicious for now
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