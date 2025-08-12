

import json
from datetime import datetime, timedelta

import uvicorn
from fastapi import (
    FastAPI,
    Depends,
    BackgroundTasks,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext
from jose import JWTError, jwt

from database import engine, Base, get_db
from schemas import (
    EntryCreate,
    EntryResponse,
    UserCreate,
    UserRead,
    Token,
    EntryUpdate,
)
from crud import (
    create_entry,
    list_entries,
    get_entry_by_id,
    update_entry_by_id,
    delete_entry_by_id,
    get_user_by_username,
    create_user,
    delete_entries_by_group,
    toggle_active,
    patch_entry_by_id,
)

app = FastAPI(title="Async Entries API")

# ─────────────────────────────────────────────────────────────────────────────
# JWT / Auth config
# ─────────────────────────────────────────────────────────────────────────────
SECRET_KEY = "super_secret_key"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
#This initializes the CryptContext object from the passlib library, which is used to handle password hashing
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# FastAPI will automatically generate the dependency that extracts the token
# from the `Authorization` header *and* document the `/token` endpoint - THIS is where we've used bearer authentication


def verify_password(plain_pw: str, hashed_pw: str) -> bool:
    """
    This function checks whether a given plain-text password (plain_pw) 
    matches a hashed password (hashed_pw) stored in the database
    """
    # Helper that delegates to passlib – *never* compare passwords manually.
    return pwd_context.verify(plain_pw, hashed_pw)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def authenticate_user(db: AsyncSession, username: str, password: str):
    # Called by the /token route.  Returns `User` on success or `None` on failure
    # so that the caller can decide how to respond.
    user = await get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    # Dependency used by every protected route.  Decodes the JWT and fetches the
    # corresponding `User` row; raises HTTP 401 if anything fails.
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        # if something goes wrong during the token validation process, we set the HTTP status code to 401 Unauthorized
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if not username:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    user = await get_user_by_username(db, username)
    if not user:
        raise credentials_exc
    return user



@app.patch(
    "/entries/{entry_id}",
    response_model=EntryResponse,
    summary="Partially update an entry"
)
async def patch_entry(
    entry_id: int,
    payload: EntryUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):
    #update_data = payload.model_dump(exclude_unset=True) # THIS is the method extracts the data from payload and ignores any 
    #fields that haven't been provided
    #entry = await update_entry_by_id(db, entry_id, update_data, current_user.id)

    update_data = payload.model_dump(exclude_unset=True)
    # `.model_dump(exclude_unset=True)` gives us only the keys that were sent in
    # the PATCH payload; we then add/override `modifiedBy`.
    update_data["modifiedBy"] = current_user.username
    owner_id = None if current_user.is_admin else current_user.id
    entry = await patch_entry_by_id(db, entry_id, update_data, owner_id)

    if not entry:
        raise EntryNotFound(entry_id)
    return EntryResponse.from_orm(entry) 
"""
return EntryResponse.from_orm(entry) - This converts the entry (which is an SQLAlchemy model) into the EntryResponse 
Pydantic schema to be returned in the response.

from_orm is a method that helps convert database models (ORM models) to Pydantic models. 
    
"""

@app.get(
    "/entries/",
    response_model=list[EntryResponse],
    summary="List all entries (with pagination & filters)"
)
async def get_all_entries(
    skip: int = 0,
    limit: int = 50,
    active: bool | None = None,
    group_name: str | None = None,
    owner_username: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):
    """List entries.
    - Regular user: only their own entries.
    - Admin user: can optionally supply `owner_username` to view another user's entries.
    """

    target_owner_id: int | None = current_user.id

    # If the requester is admin and a target username is provided, fetch that user.
    if current_user.is_admin and owner_username:
        target_user = await get_user_by_username(db, owner_username)
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found")
        target_owner_id = target_user.id

    # For admin without specifying owner, we pass None to fetch *all* entries
    if current_user.is_admin and owner_username is None:
        target_owner_id = None
        # `None` owner_id in `crud.list_entries` means *no owner filter* – admins see
        # everything.

    entries = await list_entries(
        db,
        owner_id=target_owner_id,
        skip=skip,
        limit=limit,
        active=active,
        group_name=group_name,
    )
    return [EntryResponse.from_orm(e) for e in entries]




@app.delete(
    "/entries/group/{group_name}",
    response_model=int,
    summary="Delete all entries in a group"
)
async def delete_group(
    group_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):
    owner_id = None if current_user.is_admin else current_user.id
    deleted = await delete_entries_by_group(db, owner_id, group_name)
    return deleted

@app.patch(
    "/entries/{entry_id}/active",
    response_model=EntryResponse,
    summary="Toggle an entry's active flag"
)
async def set_active(
    entry_id: int,
    active: bool,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):
    owner_id = None if current_user.is_admin else current_user.id
    entry = await toggle_active(db, entry_id, owner_id, active)
    if not entry:
        raise EntryNotFound(entry_id)
    return EntryResponse.from_orm(entry)


# ─────────────────────────────────────────────────────────────────────────────
# 1) Custom exception for "not found"
# ─────────────────────────────────────────────────────────────────────────────
class EntryNotFound(Exception):
    def __init__(self, entry_id: int):
        self.entry_id = entry_id


@app.exception_handler(EntryNotFound)
async def entry_not_found_exception_handler(request: Request, exc: EntryNotFound):
    return JSONResponse(
        status_code=404,
        content={
            "error_code": 4041,
            "message": f"Entry {exc.entry_id} not found."
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2) Create tables on startup
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ─────────────────────────────────────────────────────────────────────────────
# 3) POST /entries/  (Create a new entry)
# ─────────────────────────────────────────────────────────────────────────────
@app.post(
    "/entries/",
    response_model=EntryResponse,
    status_code=201,
    summary="Create a new entry"
)
async def post_entry(
    payload: EntryCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):
    # Ensure createdBy / modifiedBy reflect the creator
    payload_data = payload.model_dump()
    # We clone the payload so we can safely mutate without touching the original
    # `EntryCreate` instance (pydantic models are immutable by default).
    if not payload_data.get("createdBy"):
        payload_data["createdBy"] = current_user.username
    payload_data["modifiedBy"] = current_user.username

    new_payload = EntryCreate(**payload_data)

    try:
        entry = await create_entry(db, new_payload, owner_id=current_user.id)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Could not save entry: {e}")

    # Example background task
    def background_task_example(entry_id: int):
        print(f"[Background] Processing entry {entry_id} at {datetime.utcnow().isoformat()}")

    background_tasks.add_task(background_task_example, entry.id)

    return EntryResponse(
        id=entry.id,
        UserName=entry.UserName,
        AppName=entry.AppName,
        prompt=entry.prompt,
        prompt_name=entry.prompt_name,
        user_prompt=entry.user_prompt,
        group_name=entry.group_name,
        sample_output=entry.sample_output,
        #tags=json.loads(entry.tags),
        tags = entry.tags,
        createdBy=entry.createdBy,
        modifiedBy=entry.modifiedBy,
        active=entry.active,
        created_at=entry.created_at,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4) GET /entries/{entry_id}  (Retrieve a single entry)
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    "/entries/{entry_id}",
    response_model=EntryResponse,
    summary="Get one entry by ID"
)
async def get_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):
    owner_id = None if current_user.is_admin else current_user.id
    entry = await get_entry_by_id(db, entry_id, owner_id=owner_id)
    if not entry:
        raise EntryNotFound(entry_id)
    return EntryResponse(
        id=entry.id,
        UserName=entry.UserName,
        AppName=entry.AppName,
        prompt=entry.prompt,
        prompt_name=entry.prompt_name,
        user_prompt=entry.user_prompt,
        group_name=entry.group_name,
        sample_output=entry.sample_output,
        #tags=json.loads(entry.tags),
        tags = entry.tags,
        createdBy=entry.createdBy,
        modifiedBy=entry.modifiedBy,
        active=entry.active,
        created_at=entry.created_at,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5) PUT /entries/{entry_id}  (Replace an existing entry)
# ─────────────────────────────────────────────────────────────────────────────
@app.put(
    "/entries/{entry_id}",
    response_model=EntryResponse,
    summary="Update (replace) an existing entry"
)
async def replace_entry(
    entry_id: int,
    payload: EntryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):  
    """
    Replaces an existing Entry with new data:
      1. Check existence. If not found, raise EntryNotFound → 404.
      2. Attempt to update via crud.update_entry_by_id.
      3. On commit failure, rollback and return HTTP 400.
      4. Return the updated EntryResponse.
    """
    owner_id = None if current_user.is_admin else current_user.id
    existing = await get_entry_by_id(db, entry_id, owner_id=owner_id)
    if not existing:
        raise EntryNotFound(entry_id)

    # Force modifiedBy to current user
    p_data = payload.model_dump()
    # Overwrite modifiedBy irrespective of what the client sent.
    p_data["modifiedBy"] = current_user.username
    upd_payload = EntryCreate(**p_data)

    try:
        updated = await update_entry_by_id(
            db, entry_id, upd_payload, owner_id=owner_id
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Could not update entry: {e}")

    return EntryResponse(
        id=updated.id,
        UserName=updated.UserName,
        AppName=updated.AppName,
        prompt=updated.prompt,
        prompt_name=updated.prompt_name,
        user_prompt=updated.user_prompt,
        group_name=updated.group_name,
        sample_output=updated.sample_output,
        #tags=json.loads(updated.tags),
        tags = updated.tags,
        createdBy=updated.createdBy,
        modifiedBy=updated.modifiedBy,
        active=updated.active,
        created_at=updated.created_at,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6) DELETE /entries/{entry_id}  (Delete an entry)
# ─────────────────────────────────────────────────────────────────────────────
@app.delete(
    "/entries/{entry_id}",
    status_code=204,
    summary="Delete an entry"
)
async def delete_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: UserRead = Depends(get_current_user),
):

    """
    Deletes the Entry with the given ID:
      1. Check existence. If not found, raise EntryNotFound → 404.
      2. Attempt to delete via crud.delete_entry_by_id.
      3. On commit failure, rollback and return HTTP 400.
      4. Return 204 No Content on success.
    """
    owner_id = None if current_user.is_admin else current_user.id
    existing = await get_entry_by_id(db, entry_id, owner_id=owner_id)
    if not existing:
        raise EntryNotFound(entry_id)

    try:
        success = await delete_entry_by_id(
            db, entry_id, owner_id=owner_id
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Could not delete entry: {e}")

    if not success:
        raise EntryNotFound(entry_id)
    return


# ─────────────────────────────────────────────────────────────────────────────
# 8) Signup & Token routes
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/signup", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def signup(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    if await get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    return await create_user(db, user_in)


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}


# ─────────────────────────────────────────────────────────────────────────────
# 10) Current-user helper
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/me", response_model=UserRead, summary="Get details of current user")
async def read_current_user(current_user: UserRead = Depends(get_current_user)):
    """Return the UserRead object for the authenticated user."""
    # Tiny helper so the front-end can discover whether the token belongs to an
    # admin and display UI accordingly.
    return current_user


# ─────────────────────────────────────────────────────────────────────────────
# 9) Run by Python (starts Uvicorn)
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
