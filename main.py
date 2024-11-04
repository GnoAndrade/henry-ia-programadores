from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import OAuth2PasswordBearer
from typing import List, Any
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Union
import jwt
from jose import JWTError, jwt

fake_db = {"users": {}}

app = FastAPI()

class Credentials(BaseModel):
    """
    Model to represent user credentials.

    Attributes:
    username: str - The username of the user.
    password: Union[str, int] - The password of the user.
    """
    username: str
    password: Union[str, int]


class Payload(BaseModel):
    """
    Model to represent a payload containing a list of numbers.

    Attributes:
    numbers: List[int] - The list of numbers.
    """
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    """
    Model to represent a payload containing a list of numbers and a target number for binary search.

    Attributes:
    numbers: List[int] - The list of numbers.
    target: int - The target number to search for.
    """
    numbers: List[int]
    target: int

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    """
    Function to hash a password using bcrypt.

    Parameters:
    password (str): The password to hash.

    Returns:
    str: The hashed password.
    """
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """
    Function to verify a password against its hashed version.

    Parameters:
    plain_password (str): The plain password to verify.
    hashed_password (str): The hashed password to compare against.

    Returns:
    bool: True if the password matches the hashed password, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    """
    Function to create a JWT access token.

    Parameters:
    data (dict): The data to encode into the JWT.

    Returns:
    str: The JWT access token.
    """
    # This is a placeholder implementation. You should use a secret key and proper algorithm.
    return jwt.encode(data, "secret", algorithm="HS256")

credentials_exception = HTTPException(status_code=401, detail="Credenciales Inválidas / Autorización fállida.")

def verify_token(token: str = Query(None, description="JWT Token")):
    """
    Function to verify a JWT access token.

    Parameters:
    token (str): The JWT access token to verify.

    Returns:
    dict: The decoded payload from the JWT if the token is valid.

    Raises:
    HTTPException: If the token is not provided, invalid, or the user does not exist in the database.
    """
    if token is None:
        raise credentials_exception
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = fake_db["users"].get(username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

@app.post("/bubble-sort")
def bubble_sort(payload: Payload, user: dict = Depends(verify_token)):
    """
    Function to sort a list of numbers in ascending order using the bubble sort algorithm.

    Parameters:
    payload (Payload): The payload containing the list of numbers.
    user (dict): The user object obtained from the JWT token.

    Returns:
    dict: A dictionary containing the sorted list of numbers.
    """
    numbers = payload.numbers
    n = len(numbers)
    for i in range(n):
        for j in range(0, n-i-1):
            if numbers[j] > numbers[j+1]:
                numbers[j], numbers[j+1] = numbers[j+1], numbers[j]
    return {"numbers": numbers}

@app.post("/filter-even")
def filter_even(payload: Payload, user: dict = Depends(verify_token)):
    """
    Function to filter out even numbers from a list of numbers.

    Parameters:
    payload (Payload): The payload containing the list of numbers.
    user (dict): The user object obtained from the JWT token.

    Returns:
    dict: A dictionary containing the list of even numbers.
    """
    numbers = payload.numbers
    even_numbers = [num for num in numbers if num % 2 == 0]
    return {"even_numbers": even_numbers}

# Add similar middleware checks to other routes

@app.post("/sum-elements")
def sum_elements(payload: Payload, user: dict = Depends(verify_token)):
    """
    Function to calculate the sum of all numbers in a list.

    Parameters:
    payload (Payload): The payload containing the list of numbers.
    user (dict): The user object obtained from the JWT token.

    Returns:
    dict: A dictionary containing the sum of the numbers.
    """
    numbers = payload.numbers
    total_sum = sum(numbers)
    return {"sum": total_sum}

@app.post("/max-value")
def max_value(payload: Payload, user: dict = Depends(verify_token)):
    """
    Function to find the maximum value in a list of numbers.

    Parameters:
    payload (Payload): The payload containing the list of numbers.
    user (dict): The user object obtained from the JWT token.

    Returns:
    dict: A dictionary containing the maximum value.

    Raises:
    HTTPException: If the list is empty.
    """
    numbers = payload.numbers
    if not numbers:
        raise HTTPException(status_code=400, detail="List is empty")
    max_num = max(numbers)
    return {"max": max_num}

@app.post("/binary-search")
def binary_search(payload: BinarySearchPayload, user: dict = Depends(verify_token)):
    """
    Function to perform a binary search on a sorted list of numbers.

    Parameters:
    payload (BinarySearchPayload): The payload containing the sorted list of numbers and the target number.
    user (dict): The user object obtained from the JWT token.

    Returns:
    dict: A dictionary containing the result of the binary search (found or not found) and the index of the target number.
    """
    numbers = payload.numbers
    target = payload.target
    left, right = 0, len(numbers) - 1
    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            return {"found": True, "index": mid}
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return {"found": False, "index": -1}

@app.post("/register")
def register(payload: Credentials):
    """
    Function to register a new user.

    Parameters:
    payload (Credentials): The payload containing the username and password.

    Returns:
    dict: A dictionary containing a success message.

    Raises:
    HTTPException: If the user already exists.
    """
    username = payload.username
    password = str(payload.password)
    if username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = get_password_hash(password)
    fake_db["users"][username] = {"password": hashed_password}
    print(fake_db)
    return {"message": "User registered successfully"}

@app.post("/login")
def login(payload: Credentials):
    """
    Function to log in a user.

    Parameters:
    payload (Credentials): The payload containing the username and password.

    Returns:
    dict: A dictionary containing the JWT access token.

    Raises:
    HTTPException: If the credentials are invalid.
    """
    username = payload.username
    password = str(payload.password)  # Convertir el password a cadena
    if username not in fake_db["users"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = fake_db["users"][username]
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token}