"""
===========================================================
Secure Password Manager - Chrome Native Messaging Host
===========================================================

This program connects the Chrome extension to the
encrypted Python password vault.

FEATURES
-----------------------------------------------------------
- Chrome <-> Python communication
- List accounts
- Search accounts
- Verify master password
- Retrieve and decrypt a selected password

SECURITY
-----------------------------------------------------------
- Master password is never stored by this program.
- The master password is verified using the same
  PBKDF2-HMAC-SHA256 method as the desktop application.
- Account passwords remain encrypted in SQLite.
- A password is returned only after successful
  master-password verification.
- Passwords are not returned when listing accounts.

===========================================================
"""

# =========================================================
# IMPORTS
# =========================================================

import sys
import json
import struct
import sqlite3
import os
import hashlib
import secrets
import base64

from cryptography.fernet import Fernet


# =========================================================
# DATABASE LOCATION
# =========================================================

DATABASE_PATH = os.path.join(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ),
    "password_manager.db"
)


# =========================================================
# SEND MESSAGE TO CHROME
# =========================================================

def send_message(message):
    """
    Send one JSON message to Chrome.

    Native Messaging format:

        4-byte message length
        JSON message
    """

    encoded_message = json.dumps(
        message
    ).encode("utf-8")

    message_length = struct.pack(
        "<I",
        len(encoded_message)
    )

    sys.stdout.buffer.write(
        message_length
    )

    sys.stdout.buffer.write(
        encoded_message
    )

    sys.stdout.buffer.flush()


# =========================================================
# RECEIVE MESSAGE FROM CHROME
# =========================================================

def receive_message():
    """
    Receive one JSON message from Chrome.
    """

    raw_length = (
        sys.stdin.buffer.read(4)
    )

    if not raw_length:
        return None

    if len(raw_length) != 4:
        raise ValueError(
            "Invalid Native Messaging header."
        )

    message_length = struct.unpack(
        "<I",
        raw_length
    )[0]

    # Prevent unreasonable input sizes.
    if message_length > 1024 * 1024:
        raise ValueError(
            "Message is too large."
        )

    message_data = (
        sys.stdin.buffer.read(
            message_length
        )
    )

    if len(message_data) != message_length:
        raise ValueError(
            "Incomplete Native Messaging message."
        )

    return json.loads(
        message_data.decode("utf-8")
    )


# =========================================================
# OPEN DATABASE
# =========================================================

def open_database():
    """
    Open the existing password-manager database.
    """

    if not os.path.exists(
        DATABASE_PATH
    ):

        raise FileNotFoundError(
            "Password database was not found:\n"
            + DATABASE_PATH
        )

    return sqlite3.connect(
        DATABASE_PATH
    )


# =========================================================
# HASH MASTER PASSWORD
# =========================================================

def hash_master_password(
    password,
    salt
):
    """
    Reproduce the same PBKDF2-HMAC-SHA256
    calculation used by the desktop application.
    """

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )

    return password_hash.hex()


# =========================================================
# VERIFY MASTER PASSWORD
# =========================================================

def verify_master_password(
    password
):
    """
    Verify the supplied master password against
    the hash stored in the database.
    """

    connection = open_database()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                password_hash,
                salt
            FROM master_password
            WHERE id = 1
        """)

        result = cursor.fetchone()

    finally:

        connection.close()

    if result is None:

        return False

    stored_hash = result[0]

    stored_salt = result[1]

    # Convert hexadecimal salt back to bytes.
    salt = bytes.fromhex(
        stored_salt
    )

    calculated_hash = (
        hash_master_password(
            password,
            salt
        )
    )

    return secrets.compare_digest(
        calculated_hash,
        stored_hash
    )


# =========================================================
# CREATE FERNET CIPHER
# =========================================================

def create_cipher(
    master_password
):
    """
    Create the same Fernet key used by the desktop
    application.

    IMPORTANT:
    This matches the encryption method currently used
    by your existing password_manager.py.
    """

    key = hashlib.sha256(
        master_password.encode("utf-8")
    ).digest()

    fernet_key = (
        base64.urlsafe_b64encode(
            key
        )
    )

    return Fernet(
        fernet_key
    )


# =========================================================
# GET ALL ACCOUNTS
# =========================================================

def get_accounts():
    """
    Return account information without passwords.
    """

    connection = open_database()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                website,
                username,
                category
            FROM passwords
            ORDER BY id DESC
        """)

        records = cursor.fetchall()

    finally:

        connection.close()

    accounts = []

    for record in records:

        accounts.append({

            "id": record[0],

            "website": record[1],

            "username": record[2],

            "category": record[3] or "Other"

        })

    return accounts


# =========================================================
# SEARCH ACCOUNTS
# =========================================================

def search_accounts(
    search_term
):
    """
    Search website, username, or category.

    Passwords are never included in search results.
    """

    if not isinstance(
        search_term,
        str
    ):

        raise ValueError(
            "Search term must be text."
        )

    search_term = (
        search_term.strip()
    )

    if not search_term:

        return get_accounts()

    connection = open_database()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                website,
                username,
                category
            FROM passwords
            WHERE
                website LIKE ?
                OR username LIKE ?
                OR category LIKE ?
            ORDER BY id DESC
        """, (

            f"%{search_term}%",

            f"%{search_term}%",

            f"%{search_term}%"

        ))

        records = cursor.fetchall()

    finally:

        connection.close()

    accounts = []

    for record in records:

        accounts.append({

            "id": record[0],

            "website": record[1],

            "username": record[2],

            "category": record[3] or "Other"

        })

    return accounts


# =========================================================
# GET AND DECRYPT PASSWORD
# =========================================================

def get_password(
    account_id,
    master_password
):
    """
    Verify the master password and decrypt one
    selected account password.
    """

    # -----------------------------------------------------
    # Validate account ID.
    # -----------------------------------------------------

    try:

        account_id = int(
            account_id
        )

    except (
        ValueError,
        TypeError
    ):

        raise ValueError(
            "Invalid account ID."
        )


    # -----------------------------------------------------
    # Verify master password first.
    # -----------------------------------------------------

    if not verify_master_password(
        master_password
    ):

        return {

            "success": False,

            "message":
                "Incorrect master password."

        }


    # -----------------------------------------------------
    # Get encrypted password.
    # -----------------------------------------------------

    connection = open_database()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                website,
                username,
                password,
                category
            FROM passwords
            WHERE id = ?
        """, (
            account_id,
        ))

        record = cursor.fetchone()

    finally:

        connection.close()


    if record is None:

        return {

            "success": False,

            "message":
                "Account was not found."

        }


    website = record[0]

    username = record[1]

    encrypted_password = record[2]

    category = record[3] or "Other"


    # -----------------------------------------------------
    # Create encryption cipher.
    # -----------------------------------------------------

    cipher = create_cipher(
        master_password
    )


    # -----------------------------------------------------
    # Decrypt password.
    # -----------------------------------------------------

    try:

        decrypted_password = (
            cipher.decrypt(
                encrypted_password.encode(
                    "utf-8"
                )
            ).decode(
                "utf-8"
            )
        )

    except Exception:

        return {

            "success": False,

            "message":
                "Password could not be decrypted."

        }


    # -----------------------------------------------------
    # Return password.
    # -----------------------------------------------------

    return {

        "success": True,

        "account": {

            "id": account_id,

            "website": website,

            "username": username,

            "category": category,

            "password":
                decrypted_password

        }

    }


# =========================================================
# HANDLE MESSAGE
# =========================================================

def handle_message(
    message
):
    """
    Process requests from the Chrome extension.
    """

    if not isinstance(
        message,
        dict
    ):

        return {

            "success": False,

            "message":
                "Invalid message format."

        }


    action = message.get(
        "action"
    )


    # =====================================================
    # PING
    # =====================================================

    if action == "ping":

        return {

            "success": True,

            "message":
                "Connection successful! "
                "Python Native Host is working."

        }


    # =====================================================
    # GET ACCOUNTS
    # =====================================================

    elif action == "get_accounts":

        try:

            accounts = get_accounts()

            return {

                "success": True,

                "accounts": accounts

            }

        except Exception as error:

            return {

                "success": False,

                "message": str(error)

            }


    # =====================================================
    # SEARCH
    # =====================================================

    elif action == "search_accounts":

        try:

            search_term = message.get(
                "search",
                ""
            )

            accounts = search_accounts(
                search_term
            )

            return {

                "success": True,

                "accounts": accounts

            }

        except Exception as error:

            return {

                "success": False,

                "message": str(error)

            }


    # =====================================================
    # GET PASSWORD
    # =====================================================

    elif action == "get_password":

        try:

            account_id = message.get(
                "account_id"
            )

            master_password = message.get(
                "master_password"
            )

            # Never accept an empty master password.
            if not master_password:

                return {

                    "success": False,

                    "message":
                        "Master password is required."

                }

            return get_password(
                account_id,
                master_password
            )

        except Exception as error:

            return {

                "success": False,

                "message": str(error)

            }


    # =====================================================
    # UNKNOWN ACTION
    # =====================================================

    else:

        return {

            "success": False,

            "message":
                "Unknown action: "
                + str(action)

        }


# =========================================================
# MAIN
# =========================================================

def main():

    while True:

        try:

            message = receive_message()

            if message is None:

                break

            response = handle_message(
                message
            )

            send_message(
                response
            )

        except json.JSONDecodeError:

            send_message({

                "success": False,

                "message":
                    "Invalid JSON received."

            })

        except Exception as error:

            send_message({

                "success": False,

                "message":
                    str(error)

            })


# =========================================================
# PROGRAM START
# =========================================================

if __name__ == "__main__":

    main()