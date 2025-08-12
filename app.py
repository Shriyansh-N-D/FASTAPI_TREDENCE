#app.py
import streamlit as st
import httpx  # Import httpx for asynchronous requests
import asyncio  # Import asyncio to run asynchronous functions



# ── Initialize visibility flags ────────────────────────────────────────────────
for s in [
    "entries_list",   # for list all
    "show_create",    # for create form
    "entries_view",   # for view single
    "entries_edit",   # for edit list
    "entries_delete", # for delete single
    "entries_toggle", # for toggle active
    "entries_group",  # for delete-by-group
    "entries_patch"   # for partial-update
]:
    if s not in st.session_state:
        st.session_state[s] = False



# Function to make an asynchronous API request to login
async def login_user(username: str, password: str):
    """
    This function sends a POST request to the FastAPI backend's /token endpoint
    to authenticate the user and get the access token.
    """
    url = "http://localhost:8000/token"  # FastAPI backend token endpoint
    login_payload = {"username": username, "password": password}
    
    # Perform asynchronous POST request to FastAPI
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=login_payload)
    
    return response

# Helper: create a user via the /signup endpoint
async def create_user(payload: dict):
    """POST to /signup to register a new account."""
    url = "http://localhost:8000/signup"
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload)
    return response

# Function to fetch entries from the backend
async def fetch_entries(token: str, owner_username: str | None = None):
    """
    This function sends a GET request to fetch all entries from the FastAPI backend.
    The request includes the Bearer token for authorization.
    """
    if owner_username:
        url = f"http://localhost:8000/entries/?owner_username={owner_username}"
    else:
        url = "http://localhost:8000/entries/"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
    
    return response

# Function to create a new entry in the backend
async def create_entry(token: str, payload: dict):
    """
    This function sends a POST request to the FastAPI backend to create a new entry.
    """
    url = "http://localhost:8000/entries/"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload, headers=headers)
    
    return response

# Function to update an existing entry in the backend
async def update_entry(entry_id: int, token: str, payload: dict):
    """
    This function sends a PUT request to the FastAPI backend to update an existing entry.
    """
    url = f"http://localhost:8000/entries/{entry_id}"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.put(url, json=payload, headers=headers)
    
    return response

# Function to delete an entry from the backend
async def delete_entry(entry_id: int, token: str):
    """
    This function sends a DELETE request to the FastAPI backend to delete an entry.
    """
    url = f"http://localhost:8000/entries/{entry_id}"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.delete(url, headers=headers)
    
    return response

# Fetch current user details
async def get_me(token: str):
    url = "http://localhost:8000/me"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
    return resp


# ── Helper for uniform error messages ─────────────────────────────────────────
def handle_api_error(resp, action_desc: str):
    """Display a friendly message based on common HTTP status codes."""
    if resp.status_code in (401, 403):
        st.error(f"You are not authorized to {action_desc}.")
    elif resp.status_code == 404:
        st.error("Requested resource was not found.")
    elif resp.status_code == 422:
        st.error("Invalid input; please check your data and try again.")
    else:
        st.error(f"Unable to {action_desc}. (Error {resp.status_code})")


# Set up the page title
st.title("FInal Product")

# ---------------------------------------------------------------------------
# 🔐 Authentication (Sign-up / Log-in) – always available in a slim expander
# ---------------------------------------------------------------------------
with st.expander("🔐  Sign-up / Log-in", expanded="access_token" not in st.session_state):
    st.subheader("Sign-up")

    # -------- Sign-up form ---------------------------------------------------
    with st.form("signup_form"):
        new_username  = st.text_input("New username")
        new_password  = st.text_input("New password", type="password")
        is_admin_cb   = st.checkbox("Register as admin")
        submit_signup = st.form_submit_button("Sign up")

    if submit_signup:
        if new_username and new_password:
            payload = {
                "username": new_username,
                "password": new_password,
                "is_admin": is_admin_cb,
            }
            resp = asyncio.run(create_user(payload))
            if resp.status_code == 201:
                st.success("User created – logging you in…")
                login_resp = asyncio.run(login_user(new_username, new_password))
                if login_resp.status_code == 200:
                    token = login_resp.json()["access_token"]
                    st.session_state["access_token"] = token
                    st.session_state["username"]     = new_username
                    me = asyncio.run(get_me(token))
                    st.session_state["is_admin"] = me.json().get("is_admin", False) if me.status_code==200 else False
                else:
                    st.error("Automatic login failed – please try manually.")
            else:
                st.error(f"Signup failed: {resp.text}")
        else:
            st.warning("Please fill in both username and password.")

    st.markdown("---")
    st.subheader("Log-in")

    role_choice = st.radio("Login as (visual only)", ("user", "admin"), horizontal=True, key="role_choice")
    st.session_state["role"] = role_choice
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")

    if st.button("Login"):
        if username and password:
            try:
                resp = asyncio.run(login_user(username, password))
                if resp.status_code == 200:
                    token = resp.json()["access_token"]
                    st.session_state["access_token"] = token
                    st.session_state["username"]     = username
                    me = asyncio.run(get_me(token))
                    st.session_state["is_admin"] = me.json().get("is_admin", False) if me.status_code==200 else False
                    st.success("Login successful!")
                else:
                    st.error(resp.json().get("detail", "Invalid credentials."))
            except httpx.RequestError as e:
                st.error(f"Network error: {e}")
        else:
            st.warning("Please supply both username and password.")

# ---- If not authenticated yet, stop here so the entry-management UI is not
#      rendered.  The user can still see/expand the auth panel above.
if "access_token" not in st.session_state:
    st.info("Please log-in to access the Entry Management interface.")
    st.stop()

# ---- Small logout helper in the sidebar ------------------------------------
st.sidebar.markdown("## Session")
st.sidebar.success(f"Logged in as **{st.session_state.get('username','?')}**")
if st.sidebar.button("Logout"):
    for k in ("access_token", "username", "is_admin", "entries", "role"):
        st.session_state.pop(k, None)
    # No explicit rerun needed – Streamlit reruns automatically after widget actions.

st.markdown("---")
st.header("📋 Entry Management")

# ============================
# FETCH AND DISPLAY ENTRIES
# ============================


# ── Toggle List All Entries ────────────────────────────────────────────────────
if st.button("Show/Hide All Entries"):
    # The outer button toggles a boolean; the inner section fetches data only the
    # first time we expand to avoid unnecessary network calls.
    st.session_state["entries_list"] = not st.session_state["entries_list"]
    if st.session_state["entries_list"]:
        owner_filter = None
        if st.session_state.get("is_admin"):
            owner_filter = st.text_input("Username to filter (leave blank for all users)", key="admin_owner_filter")
        
        resp = asyncio.run(fetch_entries(st.session_state["access_token"],
                                        owner_filter))
        if resp.status_code == 200:
            st.session_state["entries"] = resp.json()
        else:
            handle_api_error(resp, "view these entries")

if st.session_state["entries_list"]:
    entries = st.session_state.get("entries", [])
    if entries:
        st.table(entries)
    else:
        st.warning("No entries to show.")



    
# ============================
# CREATE NEW ENTRY
# ============================

# ── Toggle Create-Entry Form ───────────────────────────────────────────────────
if st.button("Show/Hide Create-Entry Form"):
    st.session_state["show_create"] = not st.session_state["show_create"]

if st.session_state["show_create"]:
    with st.form("create_form"):
        if st.session_state.get("role") == "user":
            UserName = st.text_input("UserName", value=st.session_state.get("username", ""), disabled=True)
        else:
            UserName = st.text_input("UserName")
        AppName       = st.text_input("AppName")
        prompt        = st.text_area("Prompt")
        prompt_name   = st.text_input("Prompt Name")
        user_prompt   = st.text_area("User Prompt")
        group_name    = st.text_input("Group Name")
        sample_output = st.text_area("Sample Output")
        tags          = st.text_input("Tags (comma separated)")
        submit        = st.form_submit_button("Create Entry")

    if submit:
        payload = {
            "UserName":      UserName,
            "AppName":       AppName or None,
            "prompt":        prompt or None,
            "prompt_name":   prompt_name or None,
            "user_prompt":   user_prompt or None,
            "group_name":    group_name or None,
            "sample_output": sample_output or None,
            "tags":          tags or "default",
            "createdBy":     st.session_state.get("username") if st.session_state.get("role") == "user" else None,
            "modifiedBy":    st.session_state.get("username") if st.session_state.get("role") == "user" else None,
        }
        resp = asyncio.run(create_entry(st.session_state["access_token"], payload))
        st.write("POST status:", resp.status_code, resp.text)
        if resp.status_code == 201:
            st.success("Entry created!")
            st.session_state["entries_list"] = False
        else:
            handle_api_error(resp, "create the entry")




# ============================
# VIEW SINGLE ENTRY BY ID
# ============================


async def fetch_entry_by_id(entry_id: int, token: str):
    """
    This function sends a GET request to fetch a single entry by its ID.
    """
    url = f"http://localhost:8000/entries/{entry_id}"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
    
    return response



# ── Toggle View Single Entry ───────────────────────────────────────────────────
if st.button("Show/Hide View-Entry Form"):
    # Shows a text-box for ID and fetch button.  We map permission errors from the
    # API into a friendlier message.
    st.session_state["entries_view"] = not st.session_state["entries_view"]

if st.session_state["entries_view"]:
    eid = st.text_input("Entry ID to view", key="view_id")
    if st.button("Fetch Entry", key="view_btn"):
        resp = asyncio.run(fetch_entry_by_id(int(eid), st.session_state["access_token"]))
        st.write("GET status:", resp.status_code, resp.text)
        if resp.status_code == 200:
            entry = resp.json()
            st.json(entry)
        else:
            handle_api_error(resp, "view this entry")

# --- Show allowed Entry IDs ---------------------------------------------------
if st.button("Show Allowed Entry IDs"):
    # Convenient helper for debugging permissions – asks the back-end "give me *all*
    # entries I can see" and lists only their IDs.
    resp = asyncio.run(fetch_entries(st.session_state["access_token"], None))
    if resp.status_code == 200:
        ids = [e["id"] for e in resp.json()]
        st.write("Accessible Entry IDs:", ids)
    else:
        st.error("Could not fetch entries list.")


# ── Toggle Edit Existing Entries ───────────────────────────────────────────────
if st.button("Show/Hide Edit-Entries"):
    # Displays an expander per entry with inline editable fields.
    st.session_state["entries_edit"] = not st.session_state["entries_edit"]
    if st.session_state["entries_edit"]:
        st.session_state["entries_list"] = False

if st.session_state["entries_edit"]:
    entries = st.session_state.get("entries", [])
    for e in entries:
        with st.expander(f"Edit Entry {e['id']}"):
            UserName      = st.text_input("UserName",      value=e["UserName"],    key=f"u1_{e['id']}")
            AppName       = st.text_input("AppName",       value=e["AppName"],     key=f"a1_{e['id']}")
            prompt        = st.text_area("Prompt",        value=e["prompt"],      key=f"p1_{e['id']}")
            prompt_name   = st.text_input("Prompt Name",   value=e["prompt_name"], key=f"pn1_{e['id']}")
            user_prompt   = st.text_area("User Prompt",   value=e["user_prompt"], key=f"up1_{e['id']}")
            group_name    = st.text_input("Group Name",    value=e["group_name"],  key=f"g1_{e['id']}")
            sample_output = st.text_area("Sample Output", value=e["sample_output"], key=f"so1_{e['id']}")
            tags          = st.text_input("Tags",          value=e["tags"],        key=f"t1_{e['id']}")
            update        = st.button(f"PUT Entry {e['id']}", key=f"put_{e['id']}")

            if update:
                payload = {
                    "UserName":      UserName,
                    "AppName":       AppName,
                    "prompt":        prompt,
                    "prompt_name":   prompt_name,
                    "user_prompt":   user_prompt,
                    "group_name":    group_name,
                    "sample_output": sample_output,
                    "tags":          tags,
                }
                resp = asyncio.run(update_entry(
                    e['id'], st.session_state["access_token"], payload))
                st.write("PUT status:", resp.status_code, resp.text)
                if resp.status_code == 200:
                    st.success("Replaced!")
                    st.session_state["entries_list"] = False
                else:
                    handle_api_error(resp, "update the entry")



# ── Toggle Delete Single Entry ─────────────────────────────────────────────────
if st.button("Show/Hide Delete-Entry Buttons"):
    # One delete button per entry.  After a successful delete we collapse the list
    # so a subsequent expand forces a fresh fetch.
    st.session_state["entries_delete"] = not st.session_state["entries_delete"]

if st.session_state["entries_delete"]:
    entries = st.session_state.get("entries", [])
    for e in entries:
        if st.button(f"DELETE Entry {e['id']}", key=f"del_{e['id']}"):
            resp = asyncio.run(delete_entry(e['id'], st.session_state["access_token"]))
            st.write("DEL status:", resp.status_code)
            if resp.status_code == 204:
                st.success("Deleted!")
                st.session_state["entries_list"] = False
            else:
                handle_api_error(resp, "delete the entry")



# ============================
# TOGGLE ACTIVE FLAG
# ============================

async def toggle_active(entry_id: int, active: bool, token: str):
    """
    This function sends a PATCH request to the backend to toggle the active flag for a given entry.
    The `active` status is passed as a query parameter.
    """
    url = f"http://localhost:8000/entries/{entry_id}/active?active={active}"  # Pass active as a query parameter
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.patch(url, headers=headers)
    
    return response

# ── Toggle Active Flag ─────────────────────────────────────────────────────────
if st.button("Show/Hide Toggle-Active Buttons"):
    # Lets the user flip the active flag for any listed entry.
    st.session_state["entries_toggle"] = not st.session_state["entries_toggle"]

if st.session_state["entries_toggle"]:
    entries = st.session_state.get("entries", [])
    for e in entries:
        if st.button(f"Toggle Active {e['id']}", key=f"tog_{e['id']}"):
            new_active = not e["active"]
            resp = asyncio.run(toggle_active(
                e['id'], new_active, st.session_state["access_token"]))
            st.write("PATCH active:", resp.status_code, resp.text)
            if resp.status_code == 200:
                st.success("Toggled!")
                st.session_state["entries_list"] = False
            else:
                handle_api_error(resp, "toggle that entry")






# ============================
# DELETE ENTRIES BY GROUP
# ============================

async def delete_entries_by_group(group_name: str, token: str):
    """
    This function sends a DELETE request to remove all entries in the specified group.
    """
    url = f"http://localhost:8000/entries/group/{group_name}"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.delete(url, headers=headers)
    
    return response



# ── Toggle Delete-Group Form ──────────────────────────────────────────────────
if st.button("Show/Hide Delete-Group Form"):
    st.session_state["entries_group"] = not st.session_state["entries_group"]

if st.session_state["entries_group"]:
    grp = st.text_input("Group name to delete", key="grp_name")
    if st.button("DELETE Group", key="grp_btn"):
        resp = asyncio.run(delete_entries_by_group(
            grp, st.session_state["access_token"]))
        st.write("DEL grp status:", resp.status_code, resp.text)
        if resp.status_code in (200, 204):
            st.success("Group cleared!")
            st.session_state["entries_list"] = False
        else:
            handle_api_error(resp, "delete that group of entries")


  

# ============================
# PARTIALLY UPDATE AN ENTRY
# ============================

async def partial_update_entry(entry_id: int, payload: dict, token: str):
    """
    This function sends a PATCH request to update specific fields of an entry.
    """
    url = f"http://localhost:8000/entries/{entry_id}"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.patch(url, json=payload, headers=headers)
    
    return response



# ── Toggle Partial-Update Form ────────────────────────────────────────────────
if st.button("Show/Hide Partial-Update Form"):
    st.session_state["entries_patch"] = not st.session_state["entries_patch"]

if st.session_state["entries_patch"]:
    pid = st.text_input("Entry ID to patch", key="patch_id2")
    entry = None
    if pid:
        r = asyncio.run(fetch_entry_by_id(
            int(pid), st.session_state["access_token"]))
        st.write("Fetch status:", r.status_code, r.text)
        if r.status_code == 200:
            entry = r.json()
        else:
            st.error("Cannot load that entry.")

    if entry:
        with st.form("patch_form2"):
            UserName      = st.text_input("UserName",      entry["UserName"])
            AppName       = st.text_input("AppName",       entry["AppName"])
            prompt        = st.text_area("Prompt",        entry["prompt"])
            prompt_name   = st.text_input("Prompt Name",   entry["prompt_name"])
            user_prompt   = st.text_area("User Prompt",   entry["user_prompt"])
            group_name    = st.text_input("Group Name",    entry["group_name"])
            sample_output = st.text_area("Sample Output", entry["sample_output"])
            tags          = st.text_input(
                                "Tags (comma separated)",
                                entry["tags"] if isinstance(entry["tags"], str)
                                else ", ".join(entry["tags"])
                            )
            submit_patch  = st.form_submit_button("Submit PATCH")

        if submit_patch:
            payload = {
                "UserName":      UserName,
                "AppName":       AppName,
                "prompt":        prompt,
                "prompt_name":   prompt_name,
                "user_prompt":   user_prompt,
                "group_name":    group_name,
                "sample_output": sample_output,
                "tags":          tags,
            }
            pr = asyncio.run(partial_update_entry(
                int(pid), payload, st.session_state["access_token"]))
            st.write("PATCH status:", pr.status_code, pr.text)
            if pr.status_code == 200:
                st.success("Patched!")
                st.session_state["entries_list"] = False
            else:
                handle_api_error(pr, "update the entry")




