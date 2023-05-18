from typing import Annotated, Optional
from jose import jwt, JWTError
from fastapi import FastAPI, Depends, HTTPException
from jwt import exceptions
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.context import CryptContext
from starlette import status
import time

app = FastAPI()

SECRET_KEY = 'e5403b2e10d566848d1d8a3b6909348f'
ALGORITHM = 'HS256'

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/token')
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

engine = create_engine("sqlite:///todos.db")
Session = sessionmaker(engine)
db = Session()
Base = declarative_base()

### создание таблиц для базы данных
class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    user_name = Column(String)
    hash_password = Column(String)
    role = Column(String)


class Todos(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True)
    todo_title = Column(String)
    todo_description = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))


Base.metadata.create_all(bind=engine)


### создание моделей запроса и отображения данных пайденктик
class TodoRequest(BaseModel):
    title: str
    description: str



### одноразовое подключение к бд
def get_db():
    try:
        yield db
    finally:
        db.close()


def create_access_token(username: str,
                        user_id: int,
                        role: str):
    expire = time.time() + 3600
    post_jwt = {'sub': username,
                'id': user_id,
                'role': role,
                'exp': expire}
    return jwt.encode(post_jwt, SECRET_KEY, algorithm=ALGORITHM)


async def decode_jwt(token: Annotated[str, Depends(oauth2_scheme)]):
    print("--------------------")
    print(token)
    print("--------------------")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("id")
        user_role: str = payload.get("role")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return {"username": username, "id": user_id, "role": user_role}
    except exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid token signature")
    except exceptions.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except exceptions.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


db_dependency = Annotated[Session, Depends(get_db)]
user_dependancy = Annotated[dict, Depends(decode_jwt)]


def check_user(user_request, passw: str, db: db_dependency):
    user = db.query(Users).filter(Users.user_name == user_request).first()
    if not user:
        raise HTTPException(status_code=401, detail="пользователь не совпадает")
    if not bcrypt_context.verify(passw, user.hash_password):
        raise HTTPException(status_code=401, detail="пароль не совпадает")

    return user


@app.post('/create_user')
def create_user(user_name_request,
                password,
                role,
                db: db_dependency,
                user: user_dependancy):
    if user is None or user.get("role") != "admin":
        raise HTTPException(status_code=401, detail="для этого действия нужны права администратора")

    ph = bcrypt_context.hash(password)
    new_user = Users(user_name=user_name_request,
                     hash_password=ph,
                     role=role)
    db.add(new_user)
    db.commit()

    return f'user -- {user_name_request} -- created' \
           f'password hash -- {ph}'


@app.get('/get_users')
def get_users(db: db_dependency, user: user_dependancy):
    if user is None or user.get("role") != "admin":
        raise HTTPException(status_code=401, detail="для этого действия нужны права администратора")

    return db.query(Users).all()


@app.post('/token')
async def token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                db: db_dependency):
    user_db = check_user(form_data.username, form_data.password, db)
    if not user_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not valiable user')
    token = create_access_token(user_db.user_name, user_db.id, user_db.role)

    return {'access_token': token, 'type_token': 'bearer'}


@app.get('/token_get')
async def index(user: user_dependancy):
    return user


@app.post('/create_material')
async def create_material(title, description, user: user_dependancy, db: db_dependency):
    new_todo = Todos(todo_title=title,
                     todo_description=description,
                     owner_id=user.get("id"))
    db.add(new_todo)
    db.commit()

    return f'новая задача: {title}, ' \
           f'сделана пользователем {user.get("id")}'


@app.get('/get_material_from_all_users')
async def get_material_from_all_users():
    all_todos = db.query(Todos).all()

    return all_todos


@app.get('/get_material_from_current_users')
async def get_material_from_current_users(user: user_dependancy,
                                          db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="user is missing")
    user_materials = db.query(Todos).filter(Todos.owner_id == user.get("id")).all()

    return user_materials

@app.put('/change_user_one_material')
async def change_material(user: user_dependancy,
                          db: db_dependency,
                          matereial_reqyest: TodoRequest,
                          todo_id: int):
    if user is None:
        raise HTTPException(status_code=401, detail="user is missing")
    material_model = db.query(Todos).filter(Todos.id == todo_id)\
        .filter(Todos.owner_id == user.get("id")).first()

    if material_model is None:
        raise HTTPException(status_code=401, detail="material or user is missing")
    material_model.todo_title = matereial_reqyest.title
    material_model.todo_description = matereial_reqyest.description

    db.add(material_model)
    db.commit()

    return f'задача {todo_id} изменена успешно'

@app.get('/who_am_i')
async def who_am_i(user: user_dependancy):
    return f'user: {user.get("username")},' \
           f' id: {user.get("id")},' \
           f' role (permission): {user.get("role")}'

@app.delete('/delete_users_material')
async def delete_users_material(db: db_dependency,
                          user: user_dependancy,
                          material_id: int):
    material_for_delete = db.query(Todos).filter(Todos.id == material_id)\
        .filter(Todos.owner_id == user.get("username")).first()
    if material_for_delete is None:
        raise HTTPException(status_code=401, detail="material is absent "
                                                    "or user does not have permission")
    db.delete(material_for_delete)
    db.commit()

    return f'materal number {material_id} had deleted'


@app.delete('/delete_users_material')
async def delete_users_material(db: db_dependency,
                          user: user_dependancy,
                          material_id: int):
    return "flkjdsjf"


@app.delete('/delete_user')
async def delete_user(db: db_dependency,
          user: user_dependancy,
          user_id: int):
    if user is None or user.get("role") != "admin":
        raise HTTPException(status_code=401, detail="material is absent ")

    user_for_delete = db.query(Users).filter(Users.id == user_id).first()
    db.delete(user_for_delete)
    db.commit()

    return f'пользователь {user_id} удален успешно'


@app.delete('/delete_all_user')
def delete_all_user(db: db_dependency):
    all = db.query(Users).all()
    db.delete(all)
    db.commit()

    return "all users deleted"
