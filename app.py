# app.py
from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse

# Import the functions from our new analyzer file
from analyzer import check_communicator, check_url, generate_report

# Initialize the Flask application
app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    """
    This is the main endpoint that Twilio will call when a message comes in.
    """
    # Get the incoming message details from Twilio
    incoming_msg = request.values.get('Body', '')
    sender_phone_number = request.values.get('From', '')

    print(f"Analyzing message: '{incoming_msg}' from {sender_phone_number}")

    # --- Run our analysis ---
    # 1. Check the sender's reputation
    report_count = check_communicator(sender_phone_number)
    
    # 2. Check for suspicious URLs in the message
    is_suspicious_url = check_url(incoming_msg)

    # 3. Generate the final user-facing report
    report_message = generate_report(report_count, is_suspicious_url)

    # --- Create and send the reply ---
    response = MessagingResponse()
    response.message(report_message)

    return str(response)

# Note: The if __name__ == '__main__': block is not needed for Render deployment
# but is good practice for local testing. We'll leave it out for simplicity.