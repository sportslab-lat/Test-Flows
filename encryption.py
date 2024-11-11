from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
import json
import os
from typing import Dict, Any
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag

app = FastAPI()

# Carga las variables de entorno
load_dotenv()

class DecryptedRequest(BaseModel):
    decryptedBody: Dict[str, Any]
    aesKeyBuffer: bytes
    initialVectorBuffer: bytes

class FlowEndpointException(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message

def decrypt_request(body, private_pem, passphrase):
    encrypted_aes_key = body['encrypted_aes_key']
    encrypted_flow_data = body['encrypted_flow_data']
    initial_vector = body['initial_vector']

    private_key = serialization.load_pem_private_key(
        private_pem.encode(),
        password=passphrase.encode(),
        backend=default_backend()
    )

    try:
        decrypted_aes_key = private_key.decrypt(
            bytes.fromhex(encrypted_aes_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        raise FlowEndpointException(
            421,
            "Failed to decrypt the request. Please verify your private key."
        )

    flow_data_buffer = bytes.fromhex(encrypted_flow_data)
    initial_vector_buffer = bytes.fromhex(initial_vector)

    tag_length = 16
    encrypted_flow_data_body = flow_data_buffer[:-tag_length]
    encrypted_flow_data_tag = flow_data_buffer[-tag_length]

    cipher = Cipher(
        algorithms.AES(decrypted_aes_key),
        modes.GCM(initial_vector_buffer),
        backend=default_backend()
    )
    decipher = cipher.decryptor()
    decipher.update(encrypted_flow_data_body) + decipher.finalize_with_tag(encrypted_flow_data_tag)

    decrypted_json_string = decipher.update(encrypted_flow_data_body) + decipher.finalize()
    return DecryptedRequest(
        decryptedBody=json.loads(decrypted_json_string.decode()),
        aesKeyBuffer=decrypted_aes_key,
        initialVectorBuffer=initial_vector_buffer
    )

def encrypt_response(response, aes_key_buffer, initial_vector_buffer):
    flipped_iv = bytes([~x & 0xFF for x in initial_vector_buffer])

    cipher = Cipher(
        algorithms.AES(aes_key_buffer),
        modes.GCM(flipped_iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    encrypted_response = encryptor.update(response.encode()) + encryptor.finalize()
    return (encryptor.update(response.encode()) + encrypted_response).hex()

# Maneja la ruta raíz
@app.post("/")
async def handle_request(request: Request):
    # Implementación de la lógica de negocio
    body = await request.json()
    private_pem = os.getenv("PRIVATE_KEY")
    passphrase = os.getenv("PASSPHRASE")

    try:
        decrypted_request = decrypt_request(body, private_pem, passphrase)
    except FlowEndpointException as e:
        return JSONResponse(status_code=e.status_code, content={"error": e.message})

    # Procesa la solicitud descifrada
    response = {"message": "Solicitud procesada correctamente"}

    encrypted_response = encrypt_response(
        json.dumps(response),
        decrypted_request.aesKeyBuffer,
        decrypted_request.initialVectorBuffer
    )

    return Response(content=encrypted_response, media_type="application/json")

if __name__ == "__app__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, ssl_keyfile="/etc/letsencrypt/live/sportslab.lat/privkey.pem", ssl_certfile="/etc/letsencrypt/live/sportslab.lat/fullchain.pem")

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)