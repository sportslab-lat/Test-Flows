from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
#from fastapi.responses import PlainTextResponse

app = FastAPI()


@app.post("/webhook/")
@app.get("/webhook/")
async def webhook_whatsapp(request: Request):
    

    if request.method == "GET":
        params = request.query_params
        if params.get('hub.verify_token') == "SportsLab":
            return params.get('hub.challenge')
        else:
            return JSONResponse(content={"detail": "Error de autenticación"}, status_code=401)
    
    data = await request.json()
    # Extraemos el número de teléfono y el mensaje
    mensaje = f"Telefono: {data['entry'][0]['changes'][0]['value']['messages'][0]['from']}"
    mensaje += f" [Mensaje: {data['entry'][0]['changes'][0]['value']['messages'][0]['text']['body']}]"
    
    print(f"mensaje:{mensaje}")

    # Escribimos el número de teléfono y el mensaje en el archivo de texto
    with open("texto.txt", "a") as f:
        f.write(mensaje)
    
    return JSONResponse(content={"status": "success"}, status_code=200)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, ssl_keyfile="/etc/letsencrypt/live/sportslab.lat/privkey.pem", ssl_certfile="/etc/letsencrypt/live/sportslab.lat/fullchain.pem")


#Codigo para verificar WebHook con Facebook
'''
@app.post("/webhook", response_class=PlainTextResponse)
@app.get("/webhook", response_class=PlainTextResponse)
async def webhook_get(request: Request):
    print(f"request:{request}")
    hub_mode = request.query_params.get("hub.mode")
    hub_challenge = request.query_params.get("hub.challenge")
    verify_token = request.query_params.get("hub.verify_token")

    if hub_mode == "subscribe" and hub_challenge:
        if verify_token != "197909944":
            raise HTTPException(status_code=403, detail="Verification token mismatch")
        return hub_challenge
    return "Hello world"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, ssl_keyfile="/etc/letsencrypt/live/sportslab.lat/privkey.pem", ssl_certfile="/etc/letsencrypt/live/sportslab.lat/fullchain.pem")

'''