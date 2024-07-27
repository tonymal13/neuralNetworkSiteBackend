from fastapi import FastAPI, Depends, HTTPException, status
from fastapi_users import FastAPIUsers, exceptions as fastapi_users_exceptions
from fastapi_users.authentication import JWTStrategy
from fastapi.security import OAuth2PasswordRequestForm
from auth.auth import auth_backend, get_jwt_strategy
from auth.database import User
from auth.manager import get_user_manager
from auth.schemas import UserRead, UserCreate
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request

app = FastAPI(title="Neural network's backend")

origins = [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)

@app.get("/auth/validate_token", tags=["auth"])
async def validate_token(request: Request, jwt_strategy: JWTStrategy = Depends(get_jwt_strategy)):
    token = request.headers.get('Authorization')
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is missing")

    token = token.replace("Bearer ", "")
    try:
        payload = jwt_strategy.decode_token(token)
        return {"valid": True}
    except Exception as e:
        return {"valid": False}

@app.post("/auth/register", tags=["auth"])
async def register(user_create: UserCreate, user_manager=Depends(get_user_manager), jwt_strategy: JWTStrategy = Depends(get_jwt_strategy)):
    try:
        user = await user_manager.create(user_create)
        token = await jwt_strategy.write_token(user)
        return {"access_token": token, "token_type": "bearer"}
    except fastapi_users_exceptions.UserAlreadyExists:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists.",
        )

@app.post("/auth/jwt/login", tags=["auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), user_manager=Depends(get_user_manager), jwt_strategy: JWTStrategy = Depends(get_jwt_strategy)):
    try:
        user = await user_manager.authenticate(form_data)
        if user is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")
        token = await jwt_strategy.write_token(user)
        return {"access_token": token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")

app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"],
)

app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
)

current_user = fastapi_users.current_user()
