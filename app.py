import os
from fastapi import FastAPI, Request, BackgroundTasks
from pydantic import BaseModel
import requests
from datetime import datetime, timedelta


from dotenv import load_dotenv

app = FastAPI()


# load the variables from .env_aad
load_dotenv('.env')

whatsapp_token = os.getenv('WHATSAPP_TOKEN')

#SERVICE_ACCOUNT_FILE = '/usr/share/python-apps/luisgt/test_flows/service_account_file.json'


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

if __name__ == "__app__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, ssl_keyfile="/etc/letsencrypt/live/sportslab.lat/privkey.pem", ssl_certfile="/etc/letsencrypt/live/sportslab.lat/fullchain.pem")
