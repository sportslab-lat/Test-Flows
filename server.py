from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import hmac
import hashlib
from typing import Dict, Any
from encryption import decrypt_request, encrypt_response, FlowEndpointException
from flow import get_next_screen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from fastapi import FastAPI, Request, Response
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

load_dotenv()

app = FastAPI()

# Carga las variables de entorno
APP_SECRET = os.getenv("APP_SECRET")

# Cargar la clave privada desde .env y reemplazar \\n por \n
PRIVATE_KEY = os.getenv("PRIVATE_KEY").replace("\\n", "\n")
PASSPHRASE = os.getenv("PASSPHRASE")

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

# Maneja la ruta GET raíz
@app.get("/")
async def handle_get_request():
    return "<pre>Nothing to see here. Checkout README.md to start.</pre>"

if __name__ == "__app__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, ssl_keyfile="/etc/letsencrypt/live/sportslab.lat/privkey.pem", ssl_certfile="/etc/letsencrypt/live/sportslab.lat/fullchain.pem")