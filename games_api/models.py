from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str = "JohnDoe"
    password: str = "password"
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class VideogameModel(BaseModel):
    name: str = "Metal Gear Solid"
    release_year: int = 1998
    developer: str = "Konami"
    image_url: str = "https://default-image-url.com/game.png"