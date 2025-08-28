from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse

# Create an instance of the Flask web application
app = Flask(__name__)

# This defines a "route". It's a specific URL endpoint.
# When Twilio sends a message, it will send it to our URL + "/webhook".
@app.route('/webhook', methods=['POST'])
def webhook():
    # Flask gives us the 'request' object, which contains all the data
    # sent by Twilio. We look inside its 'values' for the 'Body' of the message.
    incoming_msg = request.values.get('Body', '')

    print(f"Received message: '{incoming_msg}'") # This prints to our server logs for debugging

    # We create an empty response object using the Twilio library
    response = MessagingResponse()

    # We add a <Message> tag to our response with the text we want to send back
    response.message("Astra connection successful. Welcome!")

    # We convert the response object to a string and send it back to Twilio
    return str(response)