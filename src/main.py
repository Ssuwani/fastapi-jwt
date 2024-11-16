from fastapi import FastAPI
from routes import auth
from database import engine, Base

# 데이터베이스 테이블 생성
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Auth 라우터 등록
app.include_router(auth.router)


@app.get("/")
async def root():
    return {"message": "Hello root"}
