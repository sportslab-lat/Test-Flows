# main.py
from fastapi import FastAPI, Request, Response, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn
import json
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidKey
import os
import hmac
import hashlib
import base64
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

app = FastAPI()

# Environment variables
APP_SECRET = os.getenv("APP_SECRET")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
PASSPHRASE = os.getenv("PASSPHRASE", "").encode() if os.getenv("PASSPHRASE") else b""
PORT = int(os.getenv("PORT", "8080"))

class FlowEndpointException(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(message)

class EncryptedRequest(BaseModel):
    encrypted_aes_key: str
    encrypted_flow_data: str
    initial_vector: str
    
#####################app.py
# load the variables from .env_aad
load_dotenv('.env')
whatsapp_token = os.getenv('WHATSAPP_TOKEN')
#####################app.py

def decrypt_request(body: EncryptedRequest, private_pem: str, passphrase: bytes):
    try:
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_pem.encode(),
            password=passphrase
        )
        
        # Decode base64 inputs
        encrypted_aes_key = base64.b64decode(body.encrypted_aes_key)
        encrypted_flow_data = base64.b64decode(body.encrypted_flow_data)
        initial_vector = base64.b64decode(body.initial_vector)
        
        # Decrypt AES key
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Split encrypted data and auth tag
        TAG_LENGTH = 16
        encrypted_flow_data_body = encrypted_flow_data[:-TAG_LENGTH]
        auth_tag = encrypted_flow_data[- TAG_LENGTH:]
        
        # Create cipher for decryption
        cipher = Cipher(
            algorithms.AES(decrypted_aes_key),
            modes.GCM(initial_vector, auth_tag),
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        decrypted_data = decryptor.update(encrypted_flow_data_body) + decryptor.finalize()
        
        return {
            "decryptedBody": json.loads(decrypted_data),
            "aesKeyBuffer": decrypted_aes_key,
            "initialVectorBuffer": initial_vector
        }
        
    except Exception as e:
        raise FlowEndpointException(
            421,
            "Failed to decrypt the request. Please verify your private key."
        )

def encrypt_response(response: Dict[str, Any], aes_key_buffer: bytes, initial_vector_buffer: bytes) -> str:
    try:
        # Flip initial vector
        #flipped_iv = bytes(~b for b in initial_vector_buffer)
        flipped_iv = bytes([(b ^ 0xFF) & 0xFF for b in initial_vector_buffer])
        
        # Create cipher for encryption
        cipher = Cipher(
            algorithms.AES(aes_key_buffer),
            modes.GCM(flipped_iv)
        )
        encryptor = cipher.encryptor()
        
        # Encrypt response
        response_json = json.dumps(response).encode()
        encrypted_data = encryptor.update(response_json) + encryptor.finalize()
        
        # Combine encrypted data with auth tag
        combined = encrypted_data + encryptor.tag
        
        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        raise

def is_request_signature_valid(raw_body: bytes, signature_header: str) -> bool:
    if not APP_SECRET:
        print("App Secret is not set up. Please Add your app secret in /.env file to check for request validation")
        return True
        
    if not signature_header:
        return False
        
    signature = signature_header.replace("sha256=", "")
    
    expected_signature = hmac.new(
        APP_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)

#####################app.py    
def send_default_message(phone_number):
    headers = {
        "Authorization": f"Bearer {whatsapp_token}",
        "Content-Type": "application/json"
    }
    url = "https://graph.facebook.com/v20.0/502296096290060/messages"
    data = {
        "messaging_product": "whatsapp",
        "to": phone_number,
        "text": {
            "body": "Lo siento, no entendí tu solicitud. Por favor, selecciona una opción válida."
        }
    }
    response = requests.post(url, headers=headers, json=data)
    return response.json()
#####################app.py   

@app.post("/next_screen")
async def root(request: Request):
    if not PRIVATE_KEY:
        raise HTTPException(
            status_code=500,
            detail='Private key is empty. Please check your env variable "PRIVATE_KEY".'
        )
    
    # Get raw body for signature verification
    raw_body = await request.body()
    
    # Verify signature
    signature_header = request.headers.get("x-hub-signature-256")
    if not is_request_signature_valid(raw_body, signature_header):
        return Response(status_code=432)
    
    try:
        # Parse request body
        body = EncryptedRequest(**await request.json())
        
        # Decrypt request
        decrypted_request = decrypt_request(body, PRIVATE_KEY, PASSPHRASE)
        print("💬 Decrypted Request:", decrypted_request["decryptedBody"])
        
        # Get next screen
        from flow1 import get_next_screen
        screen_response = await get_next_screen(decrypted_request["decryptedBody"])
        print("👉 Response to Encrypt:", screen_response)
        
        # Encrypt response
        encrypted_response = encrypt_response(
            screen_response,
            decrypted_request["aesKeyBuffer"],
            decrypted_request["initialVectorBuffer"]
        )
        
        return Response(content=encrypted_response)
        
    except FlowEndpointException as e:
        return Response(status_code=e.status_code)
    except Exception as e:
        print("Error:", e)
        return Response(status_code=500)

#####################app.py   
# Ruta del webhook de WhatsApp
@app.post("/webhook")
async def whatsapp_webhook(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
    print(data)
    entry = data['entry'][0]['changes'][0]['value']
    message = entry.get('messages', [{}])[0]
    phone_number = message.get('from')
    id = data['entry'][0]['id']

    print(f"phone_number: {phone_number}")
    print(f"id_number: {id}")
    print(f"TOKEN: {whatsapp_token}")


    # Manejo de mensajes
    
    user_message = ''
    if 'text' in message:
        user_message = message['text'].get('body', '')
    elif 'interactive' in message:
        interactive_type = message['interactive']['type']
        if interactive_type == 'button_reply':
            user_message = message['interactive']['button_reply']['id']
        elif interactive_type == 'list_reply':
            user_message = message['interactive']['list_reply']['id']

    print(f"user_message: {user_message}")

    # Mensaje por defecto o manejo de entradas no reconocidas
    send_default_message(phone_number)
    
    return {"status": "received"}
#####################app.py   

@app.get("/")
async def home():
    return """<pre>Nothing to see here.
Checkout README.md to start.</pre>"""

#if __name__ == "__main__":
#    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)