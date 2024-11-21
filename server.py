from fastapi import FastAPI, Request, Response, BackgroundTasks,HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import hmac
import hashlib
from typing import Dict, Any
from encryption import decrypt_request, encrypt_response, FlowEndpointException
from flow import get_next_screen

#from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
import base64

from fastapi import FastAPI, Request, Response
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from responses import SCREEN_RESPONSES
import json
import requests



#load_dotenv()

app = FastAPI()


#####################server.py
class DecryptedBody(BaseModel):
    screen: str
    data: Dict[str, Any]
    version: str
    action: str
    flow_token: str
#####################server.py

# Carga las variables de entorno
APP_SECRET = os.getenv("APP_SECRET")

# Cargar la clave privada desde .env y reemplazar \\n por \n
PRIVATE_KEY = os.getenv("PRIVATE_KEY").replace("\\n", "\n")
PUBLIC_KEY = os.getenv("PUBLIC_KEY").replace("\\n", "\n")  # Asegúrate de agregar esta 
PASSPHRASE = os.getenv("PASSPHRASE")

#####################app.py
# load the variables from .env_aad
load_dotenv('.env')
whatsapp_token = os.getenv('WHATSAPP_TOKEN')
#####################app.py

'''
try:
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY.encode(),  # Convertir la clave a bytes
        password=PASSPHRASE,   # Pasar la contraseña
        backend=default_backend()
    )
except Exception as e:
    print("Error al cargar la clave privada:", e)'''

print(f"APP_SECRET:{APP_SECRET}")

class DecryptedRequest(BaseModel):
    aesKeyBuffer: str
    initialVectorBuffer: str
    decryptedBody: Dict[str, Any]

# Verifica la firma de la solicitud
async def is_request_signature_valid(request: Request):
    if not APP_SECRET:
        print("App Secret is not set up. Please Add your app secret in /.env file to check for request validation")
        return True

    signature_header = request.headers.get("x-hub-signature-256")
    if not signature_header:
        print("Error: Missing signature header")
        return False

    signature_buffer = bytes.fromhex(signature_header.replace("sha256=", ""))

    # Obtén el cuerpo de la solicitud en bytes
    request_body = await request.body()

    # Crea el HMAC
    hmac_instance = hmac.new(APP_SECRET.encode(), request_body, hashlib.sha256)
    digest_buffer = hmac_instance.digest()

    # Comparación segura usando hmac.compare_digest
    if not hmac.compare_digest(digest_buffer, signature_buffer):
        print("Error: Request Signature did not match")
        return False
    return True

# Maneja la ruta raíz
@app.post("/")
async def handle_request(request: Request):
    if not PRIVATE_KEY:
        raise Exception('Private key is empty. Please check your env variable "PRIVATE_KEY".')

    if not await is_request_signature_valid(request):
        # Agrega un contenido vacío para JSONResponse
        return JSONResponse(content={}, status_code=432)

    try:
        decrypted_request = decrypt_request(await request.json(), PRIVATE_KEY, PASSPHRASE)
    except FlowEndpointException as e:
        return JSONResponse(content={}, status_code=e.status_code)
    except Exception as e:
        print(e)
        return JSONResponse(content={}, status_code=500)

    print("Decrypted Request:", decrypted_request.decryptedBody)

    screen_response = await get_next_screen(decrypted_request.decryptedBody)
    print("Response to Encrypt:", screen_response)

    return Response(
        content=encrypt_response(screen_response, decrypted_request.aesKeyBuffer, decrypted_request.initialVectorBuffer),
        media_type="application/json"
    )

#####################server.py
async def get_next_screen(decrypted_body: DecryptedBody) -> Dict[str, Any]:
    if decrypted_body.action == "ping":
        return {"data": {"status": "active"}}

    if decrypted_body.data.get("error"):
        print(f"Error recibido desde el cliente: {decrypted_body.data}")
        return {"data": {"acknowledged": True}}

    if decrypted_body.action == "INIT":
        return {
            "screen": SCREEN_RESPONSES["APPOINTMENT"].screen,
            "data": {
                **SCREEN_RESPONSES["APPOINTMENT"].data,
                "is_location_enabled": False,
                "is_date_enabled": False,
                "is_time_enabled": False,
            },
        }

    if decrypted_body.action == "data_exchange":
        if decrypted_body.screen == "APPOINTMENT":
            return {
                "screen": SCREEN_RESPONSES["APPOINTMENT"].screen,
                "data": {
                    **SCREEN_RESPONSES["APPOINTMENT"].data,
                    "is_location_enabled": bool(decrypted_body.data.get("department")),
                    "is_date_enabled": bool(decrypted_body.data.get("department")) and bool(decrypted_body.data.get("location")),
                    "is_time_enabled": bool(decrypted_body.data.get("department")) and bool(decrypted_body.data.get("location")) and bool(decrypted_body.data.get("date")),
                    "location": SCREEN_RESPONSES["APPOINTMENT"].data["location"][:3],
                    "date": SCREEN_RESPONSES["APPOINTMENT"].data["date"][:3],
                    "time": SCREEN_RESPONSES["APPOINTMENT"].data["time"][:3],
                },
            }

        elif decrypted_body.screen == "DETAILS":
            department_name = next((dept["title"] for dept in SCREEN_RESPONSES["APPOINTMENT"].data["department"] if dept["id"] == decrypted_body.data["department"]), "")
            location_name = next((loc["title"] for loc in SCREEN_RESPONSES["APPOINTMENT"].data["location"] if loc["id"] == decrypted_body.data["location"]), "")
            date_name = next((date["title"] for date in SCREEN_RESPONSES["APPOINTMENT"].data["date"] if date["id"] == decrypted_body.data["date"]), "")

            appointment = f"{department_name} en {location_name} {date_name} a las {decrypted_body.data['time']}"
            details = f"Nombre: {decrypted_body.data['name']}\nCorreo electrónico: {decrypted_body.data['email']}\nTeléfono: {decrypted_body.data['phone']}\n{decrypted_body.data['more_details']}"

            return {
                "screen": SCREEN_RESPONSES["SUMMARY"].screen,
                "data": {
                    "appointment": appointment,
                    "details": details,
                    **decrypted_body.data,
                },
            }

        elif decrypted_body.screen == "SUMMARY":
            # Guardar la cita en la base de datos
            return {
                "screen": SCREEN_RESPONSES["SUCCESS"].screen,
                "data": {
                    "extension_message_response": {
                        "params": {
                            "flow_token": decrypted_body.flow_token,
                        },
                    },
                },
            }

        else:
            print(f"Solicitud no manejada: {decrypted_body}")
            raise ValueError(
                "Solicitud de endpoint no manejada. Asegúrate de manejar la acción y pantalla solicitada."
            )
#####################server.py    

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


def validate_key_pair(private_key_str: str, public_key_str: str, passphrase: str = None) -> bool:
    """
    Valida que una private key y public key sean pares correspondientes.
    
    Args:
        private_key_str: String de la private key en formato PEM
        public_key_str: String de la public key en formato PEM
        passphrase: Contraseña de la private key si está encriptada
    
    Returns:
        bool: True si las claves son pares válidos, False en caso contrario
    """
    try:
        # Cargar la private key
        private_key = serialization.load_pem_private_key(
            private_key_str.encode(),
            password=passphrase.encode() if passphrase else None,
            backend=default_backend()
        )

        # Cargar la public key
        public_key = serialization.load_pem_public_key(
            public_key_str.encode(),
            backend=default_backend()
        )

        # Crear un mensaje de prueba
        test_message = b"Test message for key validation"

        # Firmar con la private key
        signature = private_key.sign(
            test_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Verificar con la public key
        try:
            public_key.verify(
                signature,
                test_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    except Exception as e:
        print(f"Error validando las claves: {str(e)}")
        return False



# Maneja la ruta GET raíz
@app.get("/")
async def handle_get_request():
    return "<pre>Nothing to see here. Checkout README.md to start.</pre>"


#####################server.py
@app.post("/next_screen")
async def handle_next_screen(request: Request):
    try:
        # Obtener y mostrar el body raw
        body = await request.body()
        print(f"Raw request body: {body.decode()}")
        
        # Obtener y mostrar el JSON
        json_data = await request.json()
        print(f"JSON request data: {json_data}")
        
        decrypted_body = DecryptedBody.parse_obj(await request.json())
        print(f"decrypted_body{decrypted_body}")
        response = await get_next_screen(decrypted_body)
        return Response(content=json.dumps(response), media_type="application/json")
    
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return JSONResponse(
            content={"error": "Invalid JSON format"},
            status_code=400
        )
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        return JSONResponse(
            content={"error": "Internal server error"},
            status_code=500
        )
#####################server.py

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


@app.post("/validate")
async def validate_keys(request: Request) -> Dict[str, str]:
    try:
        print("Iniciando validación de par de claves...")
        
        if not PRIVATE_KEY or not PUBLIC_KEY:
            raise HTTPException(
                status_code=500,
                detail="Las claves no están configuradas en el servidor"
            )
            
        is_valid = validate_key_pair(PRIVATE_KEY, PUBLIC_KEY, PASSPHRASE)
        
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail="Las claves proporcionadas no son un par válido"
            )
            
        print("Par de claves validado correctamente")
        return {
            "status": "success",
            "message": "Par de claves validado correctamente"
        }
        
    except HTTPException as he:
        # Re-lanzar excepciones HTTP
        raise he
    except Exception as e:
        print(f"Error durante la validación: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error durante la validación: {str(e)}"
        )

#if __name__ == "__app__":
#    import uvicorn
#   uvicorn.run(app, host="0.0.0.0", port=8080, ssl_keyfile="/etc/letsencrypt/live/sportslab.lat/privkey.pem", ssl_certfile="/etc/letsencrypt/live/sportslab.lat/fullchain.pem")