from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="User API",
    description="register and get a user",
    version="1.0.0"
)

class User(BaseModel):
    id: int
    name: str
    email: str

@app.get("/users/{user_id}", response_model=User, summary="get a user", operation_id="get_user")
def get_user(user_id: int):
    return {"id": user_id, "name": "Taro Yamada", "email": "yamada@example.com"}

@app.post("/users", response_model=User, summary="register a user", operation_id="create_user")
def create_user(user: User):
    return user
