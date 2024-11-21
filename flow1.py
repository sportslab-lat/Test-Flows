# flow.py
from typing import Dict, Any, Optional

# Screen responses from Flow Builder
SCREEN_RESPONSES = {
    "APPOINTMENT": {
        "screen": "APPOINTMENT",
        "data": {
            "department": [
                {
                    "id": "shopping",
                    "title": "Shopping & Groceries",
                },
                {
                    "id": "clothing",
                    "title": "Clothing & Apparel",
                },
                {
                    "id": "home",
                    "title": "Home Goods & Decor",
                },
                {
                    "id": "electronics",
                    "title": "Electronics & Appliances",
                },
                {
                    "id": "beauty",
                    "title": "Beauty & Personal Care",
                },
            ],
            "location": [
                {
                    "id": "1",
                    "title": "King's Cross, London",
                },
                {
                    "id": "2",
                    "title": "Oxford Street, London",
                },
                {
                    "id": "3",
                    "title": "Covent Garden, London",
                },
                {
                    "id": "4",
                    "title": "Piccadilly Circus, London",
                },
            ],
            "is_location_enabled": True,
            "date": [
                {
                    "id": "2024-01-01",
                    "title": "Mon Jan 01 2024",
                },
                {
                    "id": "2024-01-02",
                    "title": "Tue Jan 02 2024",
                },
                {
                    "id": "2024-01-03",
                    "title": "Wed Jan 03 2024",
                },
            ],
            "is_date_enabled": True,
            "time": [
                {
                    "id": "10:30",
                    "title": "10:30",
                },
                {
                    "id": "11:00",
                    "title": "11:00",
                    "enabled": False,
                },
                {
                    "id": "11:30",
                    "title": "11:30",
                },
                {
                    "id": "12:00",
                    "title": "12:00",
                    "enabled": False,
                },
                {
                    "id": "12:30",
                    "title": "12:30",
                },
            ],
            "is_time_enabled": True,
        },
    },
    "DETAILS": {
        "screen": "DETAILS",
        "data": {
            "department": "beauty",
            "location": "1",
            "date": "2024-01-01",
            "time": "11:30",
        },
    },
    "SUMMARY": {
        "screen": "SUMMARY",
        "data": {
            "appointment": "Beauty & Personal Care Department at Kings Cross, London\nMon Jan 01 2024 at 11:30.",
            "details": "Name: John Doe\nEmail: john@example.com\nPhone: 123456789\n\nA free skin care consultation, please",
            "department": "beauty",
            "location": "1",
            "date": "2024-01-01",
            "time": "11:30",
            "name": "John Doe",
            "email": "john@example.com",
            "phone": "123456789",
            "more_details": "A free skin care consultation, please",
        },
    },
    "TERMS": {
        "screen": "TERMS",
        "data": {},
    },
    "SUCCESS": {
        "screen": "SUCCESS",
        "data": {
            "extension_message_response": {
                "params": {
                    "flow_token": "REPLACE_FLOW_TOKEN",
                    "some_param_name": "PASS_CUSTOM_VALUE",
                },
            },
        },
    },
}

async def get_next_screen(decrypted_body: Dict[str, Any]) -> Dict[str, Any]:
    screen = decrypted_body.get("screen")
    data = decrypted_body.get("data", {})
    action = decrypted_body.get("action")
    flow_token = decrypted_body.get("flow_token")
    
    # Handle health check request
    if action == "ping":
        return {"data": {"status": "active"}}
    
    # Handle error notification
    if data.get("error"):
        print("Received client error:", data)
        return {"data": {"acknowledged": True}}
    
    # Handle initial request
    if action == "INIT":
        return {
            **SCREEN_RESPONSES["APPOINTMENT"],
            "data": {
                **SCREEN_RESPONSES["APPOINTMENT"]["data"],
                "is_location_enabled": False,
                "is_date_enabled": False,
                "is_time_enabled": False,
            },
        }
    
    if action == "data_exchange":
        # Handle request based on current screen
        if screen == "APPOINTMENT":
            return {
                **SCREEN_RESPONSES["APPOINTMENT"],
                "data": {
                    **SCREEN_RESPONSES["APPOINTMENT"]["data"],
                    "is_location_enabled": bool(data.get("department")),
                    "is_date_enabled": bool(data.get("department")) and bool(data.get("location")),
                    "is_time_enabled": bool(data.get("department")) and bool(data.get("location")) and bool(data.get("date")),
                    "location": SCREEN_RESPONSES["APPOINTMENT"]["data"]["location"][:3],
                    "date": SCREEN_RESPONSES["APPOINTMENT"]["data"]["date"][:3],
                    "time": SCREEN_RESPONSES["APPOINTMENT"]["data"]["time"][:3],
                },
            }
            
        elif screen == "DETAILS":
            department_name = next(
                dept["title"]
                for dept in SCREEN_RESPONSES["APPOINTMENT"]["data"]["department"]
                if dept["id"] == data["department"]
            )
            location_name = next(
                loc["title"]
                for loc in SCREEN_RESPONSES["APPOINTMENT"]["data"]["location"]
                if loc["id"] == data["location"]
            )
            date_name = next(
                date["title"]
                for date in SCREEN_RESPONSES["APPOINTMENT"]["data"]["date"]
                if date["id"] == data["date"]
            )
            
            appointment = f"{department_name} at {location_name}\n{date_name} at {data['time']}"
            details = f"Name: {data['name']}\nEmail: {data['email']}\nPhone: {data['phone']}\n\"{data['more_details']}\""
            
            return {
                **SCREEN_RESPONSES["SUMMARY"],
                "data": {
                    "appointment": appointment,
                    "details": details,
                    **data,
                },
            }
            
        elif screen == "SUMMARY":
            return {
                **SCREEN_RESPONSES["SUCCESS"],
                "data": {
                    "extension_message_response": {
                        "params": {
                            "flow_token": flow_token,
                        },
                    },
                },
            }
    
    print("Unhandled request body:", decrypted_body)
    raise ValueError(
        "Unhandled endpoint request. Make sure you handle the request action & screen logged above."
    )