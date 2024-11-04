from fastapi import FastAPI, Request, Response
from pydantic import BaseModel
from typing import Dict, Any
from responses import SCREEN_RESPONSES
import json

app = FastAPI()

class DecryptedBody(BaseModel):
    screen: str
    data: Dict[str, Any]
    version: str
    action: str
    flow_token: str

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

@app.post("/next_screen")
async def handle_next_screen(request: Request):
    decrypted_body = DecryptedBody.parse_obj(await request.json())
    response = await get_next_screen(decrypted_body)
    return Response(content=json.dumps(response), media_type="application/json")