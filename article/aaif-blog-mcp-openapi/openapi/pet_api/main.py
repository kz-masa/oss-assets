from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Pet API",
    description="register and get a pet",
    version="1.0.0"
)

class Pet(BaseModel):
    id: int
    type: str
    name: str

@app.get("/pets/{pet_id}", response_model=Pet, summary="get a pet", operation_id="get_pet")
def get_pet(pet_id: int):
    return {"id": pet_id, "type": "dog", "name": "hachi"}

@app.post("/pets", response_model=Pet, summary="register a pet", operation_id="create_pet")
def create_user(pet: Pet):
    return pet
