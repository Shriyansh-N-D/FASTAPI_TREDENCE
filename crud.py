# crud.py


import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update as sqlalchemy_update, delete as sqlalchemy_delete
from models import Entry, User
from schemas import EntryCreate, UserCreate

# ─────────────────────────────────────────────────────────────────────────────
# 1) Create a new entry (now requires owner_id)
# ─────────────────────────────────────────────────────────────────────────────
async def create_entry(db: AsyncSession, payload: EntryCreate, owner_id: int) -> Entry:
    # Convert the incoming `EntryCreate` pydantic model into an `Entry` ORM
    # instance.  We also flatten the `tags` field into a comma-separated string
    # because the DB schema stores tags as plain text.
    # Handle tags whether they are str or list
    if isinstance(payload.tags, list):
        tags_str = ",".join(payload.tags)
    elif isinstance(payload.tags, str):
        tags_str = payload.tags
    else:
        tags_str = 'default'
    entry = Entry(
        UserName=payload.UserName,
        AppName=payload.AppName,
        prompt=payload.prompt,
        prompt_name=payload.prompt_name,
        user_prompt=payload.user_prompt,
        group_name=payload.group_name,
        sample_output=payload.sample_output,
        tags=tags_str,
        createdBy=payload.createdBy,
        modifiedBy=payload.modifiedBy,
        active=payload.active,
        owner_id=owner_id,  # Ensure owner_id is passed
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry

# ─────────────────────────────────────────────────────────────────────────────
# 2) List all entries (with pagination & filtering)
# ─────────────────────────────────────────────────────────────────────────────
async def list_entries(
    db: AsyncSession,
    owner_id: int | None = None,
    skip: int = 0,
    limit: int = 50,
    active: bool | None = None,
    group_name: str | None = None,
) -> list[Entry]:
    # Return a **list** (not generator) so that the API layer can safely iterate
    # after the session closes.  Filtering is optional; passing `None` for
    # owner_id allows an admin to retrieve every record.
    stmt = select(Entry)
    if owner_id is not None:
        stmt = stmt.where(Entry.owner_id == owner_id)
    if active is not None:
        stmt = stmt.where(Entry.active == active)
    if group_name is not None:
        stmt = stmt.where(Entry.group_name == group_name)
    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()

# ─────────────────────────────────────────────────────────────────────────────
# 3) Get a single entry by ID (for a given user)
# ─────────────────────────────────────────────────────────────────────────────
async def get_entry_by_id(
    db: AsyncSession,
    entry_id: int,
    owner_id: int | None = None,
) -> Entry | None:
    stmt = select(Entry).where(Entry.id == entry_id)
    if owner_id is not None:
        stmt = stmt.where(Entry.owner_id == owner_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()

# ─────────────────────────────────────────────────────────────────────────────
# 4) Update an existing entry by ID (for a given user)
# ─────────────────────────────────────────────────────────────────────────────
async def update_entry_by_id(
    db: AsyncSession,
    entry_id: int,
    payload: EntryCreate,
    owner_id: int | None = None,
) -> Entry | None:
    # Full update – all columns replaced regardless of which fields changed.  Used
    # by the HTTP PUT handler in main.py.
    entry = await get_entry_by_id(db, entry_id, owner_id)
    if not entry:
        return None

    # Handle tags whether they are str or list
    if isinstance(payload.tags, list):
        tags_str = ",".join(payload.tags)
    elif isinstance(payload.tags, str):
        tags_str = payload.tags
    else:
        tags_str = 'default'
    stmt = (
        sqlalchemy_update(Entry)
        .where(Entry.id == entry_id)
    )
    if owner_id is not None:
        stmt = stmt.where(Entry.owner_id == owner_id)

    await db.execute(
        stmt.values(
            UserName=payload.UserName,
            AppName=payload.AppName,
            prompt=payload.prompt,
            prompt_name=payload.prompt_name,
            user_prompt=payload.user_prompt,
            group_name=payload.group_name,
            sample_output=payload.sample_output,
            tags=tags_str,
            createdBy=payload.createdBy,
            modifiedBy=payload.modifiedBy,
            active=payload.active,
        )
    )
    await db.commit()
    await db.refresh(entry)
    return entry

# ─────────────────────────────────────────────────────────────────────────────
# 5) Delete an entry by ID (for a given user)
# ─────────────────────────────────────────────────────────────────────────────
async def delete_entry_by_id(
    db: AsyncSession,
    entry_id: int,
    owner_id: int | None = None,
) -> bool:
    entry = await get_entry_by_id(db, entry_id, owner_id)
    if not entry:
        return False

    stmt = sqlalchemy_delete(Entry).where(Entry.id == entry_id)
    if owner_id is not None:
        stmt = stmt.where(Entry.owner_id == owner_id)

    await db.execute(stmt)
    await db.commit()
    return True

# ─────────────────────────────────────────────────────────────────────────────
# 6) Bulk-by-group deletion
# ─────────────────────────────────────────────────────────────────────────────
async def delete_entries_by_group(
    db: AsyncSession,
    owner_id: int | None,
    group_name: str,
) -> int:
    stmt = sqlalchemy_delete(Entry).where(Entry.group_name == group_name)
    if owner_id is not None:
        stmt = stmt.where(Entry.owner_id == owner_id)

    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount

# ─────────────────────────────────────────────────────────────────────────────
# 7) Toggle Active field
# ─────────────────────────────────────────────────────────────────────────────
async def toggle_active(
    db: AsyncSession,
    entry_id: int,
    owner_id: int | None,
    active: bool
) -> Entry | None:
    stmt = sqlalchemy_update(Entry).where(Entry.id == entry_id)
    if owner_id is not None:
        stmt = stmt.where(Entry.owner_id == owner_id)

    result = await db.execute(stmt.values(active=active))
    if result.rowcount == 0:
        return None
    await db.commit()
    return await get_entry_by_id(db, entry_id, owner_id)

# ─────────────────────────────────────────────────────────────────────────────
# User helper functions (unchanged)
# ─────────────────────────────────────────────────────────────────────────────
async def get_user_by_username(
    db: AsyncSession,
    username: str,
) -> User | None:
    result = await db.execute(
        select(User).where(User.username == username)
    )
    return result.scalar_one_or_none()

async def create_user(
    db: AsyncSession,
    user: UserCreate,
) -> User:
    """
    Create a new User in the DB.
    - Hash the incoming password.
    - Commit & refresh to get the new id.
    """
    from passlib.context import CryptContext
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

    hashed_pw = pwd_ctx.hash(user.password)
    db_user = User(
        username=user.username,
        hashed_password=hashed_pw,
        is_admin=user.is_admin if hasattr(user, "is_admin") else False,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user
from sqlalchemy import update as sqlalchemy_update

async def patch_entry_by_id(
    db: AsyncSession,
    entry_id: int,
    updates: dict,
    owner_id: int | None = None,
) -> Entry | None:
    """
    Partially update only the fields in `updates` for entry with entry_id,
    but only if it belongs to owner_id. Returns the updated Entry or None.
    """
    # If tags is provided as a list, turn into your stored string format
    if "tags" in updates and isinstance(updates["tags"], list):
        # either JSON or comma-join; here we JSON-encode for round-trip safety:
        updates["tags"] = json.dumps(updates["tags"])

    stmt = sqlalchemy_update(Entry).where(Entry.id == entry_id)
    if owner_id is not None:
        stmt = stmt.where(Entry.owner_id == owner_id)

    result = await db.execute(stmt.values(**updates))
    if result.rowcount == 0:
        return None

    await db.commit()
    # Re-fetch the row so we have an ORM object to return
    return await get_entry_by_id(db, entry_id, owner_id)

