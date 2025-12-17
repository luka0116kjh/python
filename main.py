from fastapi import FastAPI, HTTPException

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello Backend"}

@app.get("/hello")
def hello(name: str = "world"):
    return {"hello": name}

@app.get("/users/{user_id}")
def get_user(user_id: int):
    if user_id == 1:
        return {"user_id": user_id, "name": "Luka"}
    else:
        raise HTTPException(status_code=404, detail="User not found")
