from pydantic import BaseModel
from typing import Dict, Any

class ScreenResponse(BaseModel):
    screen: str
    data: Dict[str, Any]

SCREEN_RESPONSES = {
    "APPOINTMENT": ScreenResponse(
        screen="APPOINTMENT",
        data={
            "department": [
                {"id": "shopping", "title": "Shopping & Groceries"},
                {"id": "clothing", "title": "Clothing & Apparel"},
                {"id": "home", "title": "Home Goods & Decor"},
                {"id": "electronics", "title": "Electronics & Appliances"},
                {"id": "beauty", "title": "Beauty & Personal Care"},
            ],
            "location": [
                {"id": "1", "title": "King’s Cross, London"},
                {"id": "2", "title": "Oxford Street, London"},
                {"id": "3", "title": "Covent Garden, London"},
                {"id": "4", "title": "Piccadilly Circus, London"},
            ],
            "is_location_enabled": True,
            "date": [
                {"id": "2024-01-01", "title": "Mon Jan 01 2024"},
                {"id": "2024-01-02", "title": "Tue Jan 02 2024"},
                {"id": "2024-01-03", "title": "Wed Jan 03 2024"},
            ],
            "is_date_enabled": True,
            "time": [
                {"id": "10:30", "title": "10:30"},
                {"id": "11:00", "title": "11:00", "enabled": False},
                {"id": "11:30", "title": "11:30"},
                {"id": "12:00", "title": "12:00", "enabled": False},
                {"id": "12:30", "title": "12:30"},
            ],
            "is_time_enabled": True,
        },
    ),
    "DETAILS": ScreenResponse(
        screen="DETAILS",
        data={
            "department": "beauty",
            "location": "1",
            "date": "2024-01-01",
            "time": "11:30",
        },
    ),
    "SUMMARY": ScreenResponse(
        screen="SUMMARY",
        data={
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
    ),
    "TERMS": ScreenResponse(
        screen="TERMS",
        data={},
    ),
    "SUCCESS": ScreenResponse(
        screen="SUCCESS",
        data={
            "extension_message_response": {
                "params": {
                    "flow_token": "REPLACE_FLOW_TOKEN",
                    "some_param_name": "PASS_CUSTOM_VALUE",
                },
            },
        },
    ),
}