
# =========================================================
# 1. IMPORTS
# =========================================================

import tkinter as tk
from tkinter import ttk, messagebox

import sqlite3
import hashlib
import secrets
import base64
import string

import pyperclip

from cryptography.fernet import Fernet


# =========================================================
# 2. DATABASE CONFIGURATION
# =========================================================

DATABASE_NAME = "password_manager.db"


# =========================================================
# 3. DATABASE CREATION
# =========================================================

def create_database():
    """
    Create the database and required tables.

    If an older version of the application already created
    the database, the function also adds the newer category
    and notes columns.
    """

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    # -----------------------------------------------------
    # Password table
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            website TEXT NOT NULL,

            username TEXT NOT NULL,

            password TEXT NOT NULL,

            category TEXT DEFAULT 'Other',

            notes TEXT DEFAULT ''

        )
    """)

    # -----------------------------------------------------
    # Master password table
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS master_password (

            id INTEGER PRIMARY KEY,

            password_hash TEXT NOT NULL,

            salt TEXT NOT NULL

        )
    """)

    # -----------------------------------------------------
    # Check existing columns
    # -----------------------------------------------------

    cursor.execute(
        "PRAGMA table_info(passwords)"
    )

    columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    # Add category if an older database doesn't have it.
    if "category" not in columns:

        cursor.execute("""
            ALTER TABLE passwords
            ADD COLUMN category TEXT DEFAULT 'Other'
        """)

    # Add notes if an older database doesn't have it.
    if "notes" not in columns:

        cursor.execute("""
            ALTER TABLE passwords
            ADD COLUMN notes TEXT DEFAULT ''
        """)

    connection.commit()

    connection.close()


# =========================================================
# 4. MASTER PASSWORD HASHING
# =========================================================

def hash_password(password, salt=None):
    """
    Hash the master password using PBKDF2-HMAC-SHA256.

    The master password itself is never stored.

    Returns:
        password_hash
        salt
    """

    # Create a new random salt.
    if salt is None:

        salt = secrets.token_bytes(16)

    else:

        salt = bytes.fromhex(salt)

    # PBKDF2 performs many hashing iterations.
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )

    return (
        password_hash.hex(),
        salt.hex()
    )


# =========================================================
# 5. CHECK MASTER PASSWORD EXISTENCE
# =========================================================

def master_password_exists():
    """
    Check whether the application has already been
    configured with a master password.
    """

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM master_password
        WHERE id = 1
    """)

    result = cursor.fetchone()

    connection.close()

    return result is not None


# =========================================================
# 6. SAVE MASTER PASSWORD
# =========================================================

def save_master_password(password):
    """
    Store the hash and salt of the master password.
    """

    password_hash, salt = hash_password(
        password
    )

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO master_password
        (
            id,
            password_hash,
            salt
        )
        VALUES
        (
            1,
            ?,
            ?
        )
    """, (
        password_hash,
        salt
    ))

    connection.commit()

    connection.close()


# =========================================================
# 7. VERIFY MASTER PASSWORD
# =========================================================

def verify_master_password(password):
    """
    Verify a login attempt.

    The entered password is hashed with the stored salt
    and compared with the stored hash.
    """

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT password_hash, salt
        FROM master_password
        WHERE id = 1
    """)

    result = cursor.fetchone()

    connection.close()

    if result is None:

        return False

    stored_hash = result[0]

    stored_salt = result[1]

    new_hash, _ = hash_password(
        password,
        stored_salt
    )

    # Constant-time comparison.
    return secrets.compare_digest(
        new_hash,
        stored_hash
    )


# =========================================================
# 8. CREATE ENCRYPTION KEY
# =========================================================

def create_encryption_key(master_password):
    """
    Create a Fernet encryption object.

    The encryption object exists while the vault is
    unlocked.
    """

    # SHA-256 produces 32 bytes.
    key = hashlib.sha256(
        master_password.encode("utf-8")
    ).digest()

    # Fernet requires URL-safe Base64.
    fernet_key = base64.urlsafe_b64encode(
        key
    )

    return Fernet(
        fernet_key
    )


# =========================================================
# 9. PASSWORD STRENGTH CHECKER
# =========================================================

def check_password_strength(password):
    """
    Educational password-strength checker.

    The score considers:
        - Length
        - Lowercase
        - Uppercase
        - Numbers
        - Symbols
    """

    score = 0

    # Length checks.
    if len(password) >= 8:

        score += 1

    if len(password) >= 12:

        score += 1

    if len(password) >= 16:

        score += 1

    # Lowercase.
    if any(
        character.islower()
        for character in password
    ):

        score += 1

    # Uppercase.
    if any(
        character.isupper()
        for character in password
    ):

        score += 1

    # Numbers.
    if any(
        character.isdigit()
        for character in password
    ):

        score += 1

    # Symbols.
    if any(
        character in string.punctuation
        for character in password
    ):

        score += 1

    # Convert score to description.
    if score <= 2:

        return "Weak"

    elif score <= 4:

        return "Medium"

    elif score <= 6:

        return "Strong"

    else:

        return "Very Strong"


# =========================================================
# 10. SECURE PASSWORD GENERATOR
# =========================================================

def generate_secure_password(length=16):
    """
    Generate a random password using the secrets module.

    At least one character from each category is included.
    """

    lowercase = string.ascii_lowercase

    uppercase = string.ascii_uppercase

    numbers = string.digits

    symbols = string.punctuation

    # Guarantee all four character types.
    password_characters = [

        secrets.choice(
            lowercase
        ),

        secrets.choice(
            uppercase
        ),

        secrets.choice(
            numbers
        ),

        secrets.choice(
            symbols
        )
    ]

    # All available characters.
    all_characters = (
        lowercase
        + uppercase
        + numbers
        + symbols
    )

    # Generate remaining characters.
    for _ in range(
        length - 4
    ):

        password_characters.append(
            secrets.choice(
                all_characters
            )
        )

    # Securely shuffle.
    secrets.SystemRandom().shuffle(
        password_characters
    )

    return "".join(
        password_characters
    )


# =========================================================
# 11. MAIN APPLICATION CLASS
# =========================================================

class PasswordManager:

    def __init__(self, root):

        self.root = root

        # -------------------------------------------------
        # Window settings
        # -------------------------------------------------

        self.root.title(
            "Secure Password Manager"
        )

        self.root.geometry(
            "1050x750"
        )

        self.root.minsize(
            900,
            650
        )

        # -------------------------------------------------
        # Encryption object
        # -------------------------------------------------

        self.cipher = None

        # -------------------------------------------------
        # Search
        # -------------------------------------------------

        self.search_text = tk.StringVar()

        # -------------------------------------------------
        # Password visibility
        # -------------------------------------------------

        self.password_visible = False

        # -------------------------------------------------
        # Clipboard timer
        # -------------------------------------------------

        self.clipboard_clear_job = None

        # Start authentication.
        self.show_authentication()


    # =====================================================
    # CLEAR WINDOW
    # =====================================================

    def clear_window(self):

        for widget in self.root.winfo_children():

            widget.destroy()


    # =====================================================
    # AUTHENTICATION ROUTER
    # =====================================================

    def show_authentication(self):

        self.clear_window()

        if master_password_exists():

            self.show_login()

        else:

            self.show_create_password()


    # =====================================================
    # CREATE MASTER PASSWORD SCREEN
    # =====================================================

    def show_create_password(self):

        ttk.Label(
            self.root,
            text="Create Master Password",
            font=("Arial", 22, "bold")
        ).pack(
            pady=30
        )

        ttk.Label(
            self.root,
            text=(
                "Create a master password to protect "
                "your encrypted vault."
            )
        ).pack()

        ttk.Label(
            self.root,
            text="Master Password:"
        ).pack(
            pady=(30, 5)
        )

        self.master_password_entry = ttk.Entry(
            self.root,
            show="*",
            width=35
        )

        self.master_password_entry.pack()

        ttk.Label(
            self.root,
            text="Confirm Password:"
        ).pack(
            pady=(15, 5)
        )

        self.confirm_password_entry = ttk.Entry(
            self.root,
            show="*",
            width=35
        )

        self.confirm_password_entry.pack()

        ttk.Button(
            self.root,
            text="Create Master Password",
            command=self.create_password_action
        ).pack(
            pady=30
        )


    # =====================================================
    # CREATE MASTER PASSWORD
    # =====================================================

    def create_password_action(self):

        password = (
            self.master_password_entry.get()
        )

        confirmation = (
            self.confirm_password_entry.get()
        )

        # Empty password.
        if not password:

            messagebox.showwarning(
                "Password Required",
                "Please enter a master password."
            )

            return

        # Minimum length.
        if len(password) < 8:

            messagebox.showwarning(
                "Weak Password",
                "Master password must contain "
                "at least 8 characters."
            )

            return

        # Confirmation.
        if password != confirmation:

            messagebox.showerror(
                "Password Error",
                "Passwords do not match."
            )

            return

        try:

            save_master_password(
                password
            )

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Could not save master password:\n{error}"
            )

            return

        messagebox.showinfo(
            "Success",
            "Master password created successfully."
        )

        self.show_login()


    # =====================================================
    # LOGIN SCREEN
    # =====================================================

    def show_login(self):

        self.clear_window()

        ttk.Label(
            self.root,
            text="Secure Password Manager",
            font=("Arial", 22, "bold")
        ).pack(
            pady=40
        )

        ttk.Label(
            self.root,
            text="Enter your master password"
        ).pack()

        self.login_password_entry = ttk.Entry(
            self.root,
            show="*",
            width=35
        )

        self.login_password_entry.pack(
            pady=25
        )

        ttk.Button(
            self.root,
            text="Unlock Vault",
            command=self.login_action
        ).pack()

        # Press Enter to login.
        self.login_password_entry.bind(
            "<Return>",
            lambda event: self.login_action()
        )

        self.login_password_entry.focus()


    # =====================================================
    # LOGIN ACTION
    # =====================================================

    def login_action(self):

        password = (
            self.login_password_entry.get()
        )

        if not password:

            messagebox.showwarning(
                "Password Required",
                "Please enter your master password."
            )

            return

        if verify_master_password(password):

            # Create encryption object only after
            # successful authentication.
            self.cipher = create_encryption_key(
                password
            )

            self.show_vault()

        else:

            messagebox.showerror(
                "Access Denied",
                "Incorrect master password."
            )

            self.login_password_entry.delete(
                0,
                tk.END
            )


    # =====================================================
    # MAIN VAULT SCREEN
    # =====================================================

    def show_vault(self):

        self.clear_window()

        # -------------------------------------------------
        # HEADER
        # -------------------------------------------------

        header = ttk.Frame(
            self.root
        )

        header.pack(
            fill="x",
            padx=20,
            pady=15
        )

        ttk.Label(
            header,
            text="Password Vault",
            font=("Arial", 22, "bold")
        ).pack(
            side="left"
        )

        ttk.Button(
            header,
            text="Lock Vault",
            command=self.lock_vault
        ).pack(
            side="right"
        )

        ttk.Button(
            header,
            text="Security Dashboard",
            command=self.show_dashboard
        ).pack(
            side="right",
            padx=10
        )

        # -------------------------------------------------
        # ACCOUNT INFORMATION
        # -------------------------------------------------

        input_frame = ttk.LabelFrame(
            self.root,
            text="Account Information"
        )

        input_frame.pack(
            fill="x",
            padx=20,
            pady=10
        )

        # Website.
        ttk.Label(
            input_frame,
            text="Website:"
        ).grid(
            row=0,
            column=0,
            padx=10,
            pady=8
        )

        self.website_entry = ttk.Entry(
            input_frame,
            width=28
        )

        self.website_entry.grid(
            row=0,
            column=1,
            padx=10,
            pady=8
        )

        # Username.
        ttk.Label(
            input_frame,
            text="Username:"
        ).grid(
            row=1,
            column=0,
            padx=10,
            pady=8
        )

        self.username_entry = ttk.Entry(
            input_frame,
            width=28
        )

        self.username_entry.grid(
            row=1,
            column=1,
            padx=10,
            pady=8
        )

        # Password.
        ttk.Label(
            input_frame,
            text="Password:"
        ).grid(
            row=2,
            column=0,
            padx=10,
            pady=8
        )

        self.password_entry = ttk.Entry(
            input_frame,
            width=28,
            show="*"
        )

        self.password_entry.grid(
            row=2,
            column=1,
            padx=10,
            pady=8
        )

        # Password strength while typing.
        self.password_entry.bind(
            "<KeyRelease>",
            self.password_typing
        )

        # Show / Hide.
        self.show_password_button = ttk.Button(
            input_frame,
            text="Show",
            command=self.toggle_password
        )

        self.show_password_button.grid(
            row=2,
            column=2,
            padx=5
        )

        # Category.
        ttk.Label(
            input_frame,
            text="Category:"
        ).grid(
            row=3,
            column=0,
            padx=10,
            pady=8
        )

        self.category_box = ttk.Combobox(
            input_frame,
            values=[
                "Social",
                "Email",
                "Banking",
                "Shopping",
                "Work",
                "Education",
                "Gaming",
                "Other"
            ],
            state="readonly",
            width=25
        )

        self.category_box.grid(
            row=3,
            column=1,
            padx=10,
            pady=8
        )

        self.category_box.set(
            "Other"
        )

        # Notes.
        ttk.Label(
            input_frame,
            text="Notes:"
        ).grid(
            row=4,
            column=0,
            padx=10,
            pady=8
        )

        self.notes_entry = ttk.Entry(
            input_frame,
            width=28
        )

        self.notes_entry.grid(
            row=4,
            column=1,
            padx=10,
            pady=8
        )

        # Add.
        ttk.Button(
            input_frame,
            text="Add Account",
            command=self.save_password
        ).grid(
            row=0,
            column=3,
            padx=15
        )

        # Update.
        ttk.Button(
            input_frame,
            text="Update Account",
            command=self.update_password
        ).grid(
            row=1,
            column=3,
            padx=15
        )

        # Clear.
        ttk.Button(
            input_frame,
            text="Clear",
            command=self.clear_fields
        ).grid(
            row=2,
            column=3,
            padx=15
        )

        # -------------------------------------------------
        # PASSWORD GENERATOR
        # -------------------------------------------------

        generator_frame = ttk.LabelFrame(
            self.root,
            text="Secure Password Generator"
        )

        generator_frame.pack(
            fill="x",
            padx=20,
            pady=8
        )

        ttk.Label(
            generator_frame,
            text="Length:"
        ).pack(
            side="left",
            padx=10
        )

        self.password_length = tk.IntVar(
            value=16
        )

        ttk.Spinbox(
            generator_frame,
            from_=8,
            to=64,
            textvariable=self.password_length,
            width=5
        ).pack(
            side="left"
        )

        ttk.Button(
            generator_frame,
            text="Generate Password",
            command=self.generate_password
        ).pack(
            side="left",
            padx=15
        )

        self.strength_label = ttk.Label(
            generator_frame,
            text="Strength: -"
        )

        self.strength_label.pack(
            side="left",
            padx=15
        )

        # -------------------------------------------------
        # SEARCH
        # -------------------------------------------------

        search_frame = ttk.Frame(
            self.root
        )

        search_frame.pack(
            fill="x",
            padx=20,
            pady=8
        )

        ttk.Label(
            search_frame,
            text="Search:"
        ).pack(
            side="left",
            padx=(0, 10)
        )

        ttk.Entry(
            search_frame,
            textvariable=self.search_text,
            width=35
        ).pack(
            side="left"
        )

        ttk.Button(
            search_frame,
            text="Search",
            command=self.search_passwords
        ).pack(
            side="left",
            padx=10
        )

        ttk.Button(
            search_frame,
            text="Show All",
            command=self.load_passwords
        ).pack(
            side="left"
        )

        # -------------------------------------------------
        # ACCOUNT TABLE
        # -------------------------------------------------

        table_frame = ttk.LabelFrame(
            self.root,
            text="Saved Accounts"
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=8
        )

        self.password_table = ttk.Treeview(
            table_frame,
            columns=(
                "id",
                "website",
                "username",
                "category"
            ),
            show="headings"
        )

        self.password_table.heading(
            "id",
            text="ID"
        )

        self.password_table.heading(
            "website",
            text="Website"
        )

        self.password_table.heading(
            "username",
            text="Username"
        )

        self.password_table.heading(
            "category",
            text="Category"
        )

        self.password_table.column(
            "id",
            width=50
        )

        self.password_table.column(
            "website",
            width=220
        )

        self.password_table.column(
            "username",
            width=230
        )

        self.password_table.column(
            "category",
            width=130
        )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.password_table.yview
        )

        self.password_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.password_table.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        # Selecting an account.
        self.password_table.bind(
            "<<TreeviewSelect>>",
            self.select_account
        )

        # -------------------------------------------------
        # ACTION BUTTONS
        # -------------------------------------------------

        action_frame = ttk.Frame(
            self.root
        )

        action_frame.pack(
            pady=12
        )

        ttk.Button(
            action_frame,
            text="Show Password",
            command=self.show_selected_password
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            action_frame,
            text="Copy Password",
            command=self.copy_selected_password
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            action_frame,
            text="Show Notes",
            command=self.show_selected_notes
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            action_frame,
            text="Delete Selected",
            command=self.delete_password
        ).pack(
            side="left",
            padx=5
        )

        self.load_passwords()


    # =====================================================
    # PASSWORD TYPING
    # =====================================================

    def password_typing(self, event=None):

        password = (
            self.password_entry.get()
        )

        self.update_strength_indicator(
            password
        )


    # =====================================================
    # GENERATE PASSWORD
    # =====================================================

    def generate_password(self):

        try:

            length = int(
                self.password_length.get()
            )

        except (ValueError, tk.TclError):

            messagebox.showwarning(
                "Invalid Length",
                "Please enter a valid number."
            )

            return

        if length < 8:

            length = 8

            self.password_length.set(
                length
            )

        if length > 64:

            length = 64

            self.password_length.set(
                length
            )

        password = generate_secure_password(
            length
        )

        self.password_entry.delete(
            0,
            tk.END
        )

        self.password_entry.insert(
            0,
            password
        )

        self.password_entry.config(
            show=""
        )

        self.show_password_button.config(
            text="Hide"
        )

        self.password_visible = True

        self.update_strength_indicator(
            password
        )


    # =====================================================
    # PASSWORD STRENGTH INDICATOR
    # =====================================================

    def update_strength_indicator(
        self,
        password
    ):

        if not password:

            self.strength_label.config(
                text="Strength: -"
            )

            return

        strength = (
            check_password_strength(
                password
            )
        )

        self.strength_label.config(
            text=f"Strength: {strength}"
        )


    # =====================================================
    # SHOW / HIDE PASSWORD
    # =====================================================

    def toggle_password(self):

        if self.password_visible:

            self.password_entry.config(
                show="*"
            )

            self.show_password_button.config(
                text="Show"
            )

            self.password_visible = False

        else:

            self.password_entry.config(
                show=""
            )

            self.show_password_button.config(
                text="Hide"
            )

            self.password_visible = True


    # =====================================================
    # SAVE ACCOUNT
    # =====================================================

    def save_password(self):

        website = (
            self.website_entry.get().strip()
        )

        username = (
            self.username_entry.get().strip()
        )

        password = (
            self.password_entry.get()
        )

        category = (
            self.category_box.get()
        )

        notes = (
            self.notes_entry.get().strip()
        )

        # -------------------------------------------------
        # Validation
        # -------------------------------------------------

        if not website:

            messagebox.showwarning(
                "Missing Website",
                "Please enter a website."
            )

            return

        if len(website) > 200:

            messagebox.showwarning(
                "Invalid Website",
                "Website is too long."
            )

            return

        if not username:

            messagebox.showwarning(
                "Missing Username",
                "Please enter a username."
            )

            return

        if not password:

            messagebox.showwarning(
                "Missing Password",
                "Please enter a password."
            )

            return

        if len(password) < 4:

            messagebox.showwarning(
                "Weak Password",
                "Password should contain at least "
                "4 characters."
            )

            return

        if len(notes) > 500:

            messagebox.showwarning(
                "Notes Too Long",
                "Notes cannot exceed 500 characters."
            )

            return

        # -------------------------------------------------
        # Encrypt password
        # -------------------------------------------------

        try:

            encrypted_password = (
                self.cipher.encrypt(
                    password.encode("utf-8")
                ).decode("utf-8")
            )

        except Exception as error:

            messagebox.showerror(
                "Encryption Error",
                f"Could not encrypt password:\n{error}"
            )

            return

        # -------------------------------------------------
        # Save account
        # -------------------------------------------------

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

            cursor = connection.cursor()

            cursor.execute("""
                INSERT INTO passwords
                (
                    website,
                    username,
                    password,
                    category,
                    notes
                )
                VALUES
                (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                )
            """, (
                website,
                username,
                encrypted_password,
                category,
                notes
            ))

            connection.commit()

            connection.close()

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Could not save account:\n{error}"
            )

            return

        messagebox.showinfo(
            "Success",
            "Account added successfully."
        )

        self.clear_fields()

        self.load_passwords()


    # =====================================================
    # LOAD ACCOUNTS
    # =====================================================

    def load_passwords(self):

        for item in self.password_table.get_children():

            self.password_table.delete(
                item
            )

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

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

            connection.close()

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Could not load accounts:\n{error}"
            )

            return

        for record in records:

            self.password_table.insert(
                "",
                "end",
                values=record
            )


    # =====================================================
    # SEARCH ACCOUNTS
    # =====================================================

    def search_passwords(self):

        search_term = (
            self.search_text.get().strip()
        )

        if not search_term:

            self.load_passwords()

            return

        for item in self.password_table.get_children():

            self.password_table.delete(
                item
            )

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

            cursor = connection.cursor()

            cursor.execute("""
                SELECT
                    id,
                    website,
                    username,
                    category
                FROM passwords
                WHERE website LIKE ?
                   OR username LIKE ?
                   OR category LIKE ?
                ORDER BY id DESC
            """, (
                f"%{search_term}%",
                f"%{search_term}%",
                f"%{search_term}%"
            ))

            records = cursor.fetchall()

            connection.close()

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Search failed:\n{error}"
            )

            return

        for record in records:

            self.password_table.insert(
                "",
                "end",
                values=record
            )


    # =====================================================
    # SELECT ACCOUNT
    # =====================================================

    def select_account(
        self,
        event=None
    ):

        selected = (
            self.password_table.selection()
        )

        if not selected:

            return

        record = self.password_table.item(
            selected[0]
        )

        values = record["values"]

        if not values:

            return

        password_id = values[0]

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

            cursor = connection.cursor()

            cursor.execute("""
                SELECT
                    website,
                    username,
                    password,
                    category,
                    notes
                FROM passwords
                WHERE id = ?
            """, (
                password_id,
            ))

            result = cursor.fetchone()

            connection.close()

        except sqlite3.Error:

            return

        if result is None:

            return

        website = result[0]

        username = result[1]

        encrypted_password = result[2]

        category = result[3]

        notes = result[4]

        # Decrypt.
        try:

            password = (
                self.cipher.decrypt(
                    encrypted_password.encode(
                        "utf-8"
                    )
                ).decode(
                    "utf-8"
                )
            )

        except Exception:

            messagebox.showerror(
                "Decryption Error",
                "Unable to decrypt password."
            )

            return

        # Website.
        self.website_entry.delete(
            0,
            tk.END
        )

        self.website_entry.insert(
            0,
            website
        )

        # Username.
        self.username_entry.delete(
            0,
            tk.END
        )

        self.username_entry.insert(
            0,
            username
        )

        # Password.
        self.password_entry.delete(
            0,
            tk.END
        )

        self.password_entry.insert(
            0,
            password
        )

        # Hide password after selecting.
        self.password_entry.config(
            show="*"
        )

        self.show_password_button.config(
            text="Show"
        )

        self.password_visible = False

        # Category.
        self.category_box.set(
            category or "Other"
        )

        # Notes.
        self.notes_entry.delete(
            0,
            tk.END
        )

        self.notes_entry.insert(
            0,
            notes or ""
        )

        # Strength.
        self.update_strength_indicator(
            password
        )


    # =====================================================
    # UPDATE ACCOUNT
    # =====================================================

    def update_password(self):

        selected = (
            self.password_table.selection()
        )

        if not selected:

            messagebox.showwarning(
                "No Selection",
                "Select an account to update."
            )

            return

        website = (
            self.website_entry.get().strip()
        )

        username = (
            self.username_entry.get().strip()
        )

        password = (
            self.password_entry.get()
        )

        category = (
            self.category_box.get()
        )

        notes = (
            self.notes_entry.get().strip()
        )

        if not website:

            messagebox.showwarning(
                "Missing Website",
                "Please enter a website."
            )

            return

        if not username:

            messagebox.showwarning(
                "Missing Username",
                "Please enter a username."
            )

            return

        if not password:

            messagebox.showwarning(
                "Missing Password",
                "Please enter a password."
            )

            return

        if len(notes) > 500:

            messagebox.showwarning(
                "Notes Too Long",
                "Notes cannot exceed 500 characters."
            )

            return

        record = self.password_table.item(
            selected[0]
        )

        password_id = record["values"][0]

        # Encrypt updated password.
        try:

            encrypted_password = (
                self.cipher.encrypt(
                    password.encode("utf-8")
                ).decode("utf-8")
            )

        except Exception as error:

            messagebox.showerror(
                "Encryption Error",
                f"Could not encrypt password:\n{error}"
            )

            return

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

            cursor = connection.cursor()

            cursor.execute("""
                UPDATE passwords
                SET
                    website = ?,
                    username = ?,
                    password = ?,
                    category = ?,
                    notes = ?
                WHERE id = ?
            """, (
                website,
                username,
                encrypted_password,
                category,
                notes,
                password_id
            ))

            connection.commit()

            connection.close()

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Could not update account:\n{error}"
            )

            return

        messagebox.showinfo(
            "Updated",
            "Account updated successfully."
        )

        self.clear_fields()

        self.load_passwords()


    # =====================================================
    # GET SELECTED PASSWORD
    # =====================================================

    def get_selected_password(self):

        selected = (
            self.password_table.selection()
        )

        if not selected:

            messagebox.showwarning(
                "No Selection",
                "Please select an account."
            )

            return None

        record = self.password_table.item(
            selected[0]
        )

        password_id = record["values"][0]

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

            cursor = connection.cursor()

            cursor.execute("""
                SELECT password
                FROM passwords
                WHERE id = ?
            """, (
                password_id,
            ))

            result = cursor.fetchone()

            connection.close()

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Could not retrieve password:\n{error}"
            )

            return None

        if result is None:

            return None

        try:

            return self.cipher.decrypt(
                result[0].encode(
                    "utf-8"
                )
            ).decode(
                "utf-8"
            )

        except Exception:

            messagebox.showerror(
                "Decryption Error",
                "Unable to decrypt password."
            )

            return None


    # =====================================================
    # SHOW PASSWORD
    # =====================================================

    def show_selected_password(self):

        password = (
            self.get_selected_password()
        )

        if password is None:

            return

        messagebox.showinfo(
            "Password",
            f"Password:\n\n{password}"
        )


    # =====================================================
    # COPY PASSWORD
    # =====================================================

    def copy_selected_password(self):

        password = (
            self.get_selected_password()
        )

        if password is None:

            return

        try:

            pyperclip.copy(
                password
            )

            # Cancel existing timer.
            if self.clipboard_clear_job is not None:

                try:

                    self.root.after_cancel(
                        self.clipboard_clear_job
                    )

                except Exception:

                    pass

            # Clear clipboard after 30 seconds.
            self.clipboard_clear_job = (
                self.root.after(
                    30000,
                    self.clear_clipboard
                )
            )

            messagebox.showinfo(
                "Copied",
                "Password copied to clipboard.\n\n"
                "Clipboard will be cleared after "
                "30 seconds."
            )

        except Exception as error:

            messagebox.showerror(
                "Clipboard Error",
                f"Could not copy password:\n{error}"
            )


    # =====================================================
    # CLEAR CLIPBOARD
    # =====================================================

    def clear_clipboard(self):

        try:

            pyperclip.copy("")

        except Exception:

            pass

        self.clipboard_clear_job = None


    # =====================================================
    # SHOW NOTES
    # =====================================================

    def show_selected_notes(self):

        selected = (
            self.password_table.selection()
        )

        if not selected:

            messagebox.showwarning(
                "No Selection",
                "Please select an account."
            )

            return

        record = self.password_table.item(
            selected[0]
        )

        password_id = record["values"][0]

        connection = sqlite3.connect(
            DATABASE_NAME
        )

        cursor = connection.cursor()

        cursor.execute("""
            SELECT notes
            FROM passwords
            WHERE id = ?
        """, (
            password_id,
        ))

        result = cursor.fetchone()

        connection.close()

        if result is None:

            return

        notes = result[0]

        if not notes:

            notes = "No notes saved."

        messagebox.showinfo(
            "Account Notes",
            notes
        )


    # =====================================================
    # SECURITY DASHBOARD
    # =====================================================

    def show_dashboard(self):
        """
        Display security statistics.

        Passwords are temporarily decrypted in memory to
        calculate their strength. They are not written back
        to the database in plaintext.
        """

        dashboard = tk.Toplevel(
            self.root
        )

        dashboard.title(
            "Security Dashboard"
        )

        dashboard.geometry(
            "620x600"
        )

        dashboard.resizable(
            False,
            False
        )

        # -------------------------------------------------
        # Title
        # -------------------------------------------------

        ttk.Label(
            dashboard,
            text="Security Dashboard",
            font=("Arial", 22, "bold")
        ).pack(
            pady=25
        )

        ttk.Label(
            dashboard,
            text=(
                "Overview of your password vault security"
            )
        ).pack(
            pady=(0, 20)
        )

        # -------------------------------------------------
        # Get all accounts
        # -------------------------------------------------

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

            cursor = connection.cursor()

            cursor.execute("""
                SELECT
                    website,
                    username,
                    password,
                    category
                FROM passwords
            """)

            records = cursor.fetchall()

            connection.close()

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Could not load dashboard:\n{error}"
            )

            dashboard.destroy()

            return

        # -------------------------------------------------
        # Statistics
        # -------------------------------------------------

        total_accounts = len(
            records
        )

        categories = set()

        weak_passwords = 0

        medium_passwords = 0

        strong_passwords = 0

        very_strong_passwords = 0

        decryption_errors = 0

        # -------------------------------------------------
        # Analyze accounts
        # -------------------------------------------------

        for record in records:

            encrypted_password = record[2]

            category = record[3]

            # Category count.
            if category:

                categories.add(
                    category
                )

            # Decrypt password temporarily.
            try:

                password = (
                    self.cipher.decrypt(
                        encrypted_password.encode(
                            "utf-8"
                        )
                    ).decode(
                        "utf-8"
                    )
                )

            except Exception:

                decryption_errors += 1

                continue

            # Check strength.
            strength = (
                check_password_strength(
                    password
                )
            )

            if strength == "Weak":

                weak_passwords += 1

            elif strength == "Medium":

                medium_passwords += 1

            elif strength == "Strong":

                strong_passwords += 1

            elif strength == "Very Strong":

                very_strong_passwords += 1

        # -------------------------------------------------
        # Vault statistics
        # -------------------------------------------------

        stats_frame = ttk.LabelFrame(
            dashboard,
            text="Vault Statistics"
        )

        stats_frame.pack(
            fill="x",
            padx=30,
            pady=10
        )

        ttk.Label(
            stats_frame,
            text=f"Total Accounts: {total_accounts}",
            font=("Arial", 13)
        ).pack(
            anchor="w",
            padx=20,
            pady=8
        )

        ttk.Label(
            stats_frame,
            text=f"Categories Used: {len(categories)}",
            font=("Arial", 13)
        ).pack(
            anchor="w",
            padx=20,
            pady=8
        )

        # -------------------------------------------------
        # Password strength
        # -------------------------------------------------

        strength_frame = ttk.LabelFrame(
            dashboard,
            text="Password Strength"
        )

        strength_frame.pack(
            fill="x",
            padx=30,
            pady=15
        )

        ttk.Label(
            strength_frame,
            text=f"Weak: {weak_passwords}",
            font=("Arial", 13)
        ).pack(
            anchor="w",
            padx=20,
            pady=5
        )

        ttk.Label(
            strength_frame,
            text=f"Medium: {medium_passwords}",
            font=("Arial", 13)
        ).pack(
            anchor="w",
            padx=20,
            pady=5
        )

        ttk.Label(
            strength_frame,
            text=f"Strong: {strong_passwords}",
            font=("Arial", 13)
        ).pack(
            anchor="w",
            padx=20,
            pady=5
        )

        ttk.Label(
            strength_frame,
            text=f"Very Strong: {very_strong_passwords}",
            font=("Arial", 13)
        ).pack(
            anchor="w",
            padx=20,
            pady=5
        )

        # -------------------------------------------------
        # Security recommendation
        # -------------------------------------------------

        if weak_passwords > 0:

            recommendation = (
                "Security Recommendation:\n\n"
                "You have weak passwords in your vault. "
                "Consider replacing them using the "
                "secure password generator."
            )

        elif medium_passwords > 0:

            recommendation = (
                "Security Recommendation:\n\n"
                "Some passwords could be stronger. "
                "Consider using longer randomly "
                "generated passwords."
            )

        else:

            recommendation = (
                "Security Status:\n\n"
                "Your stored passwords have good "
                "strength according to the application's "
                "password-strength checker."
            )

        # Add decryption warning if necessary.
        if decryption_errors > 0:

            recommendation += (
                "\n\nWarning: "
                f"{decryption_errors} account(s) "
                "could not be analyzed."
            )

        recommendation_frame = ttk.LabelFrame(
            dashboard,
            text="Security Status"
        )

        recommendation_frame.pack(
            fill="x",
            padx=30,
            pady=10
        )

        ttk.Label(
            recommendation_frame,
            text=recommendation,
            wraplength=500,
            justify="left"
        ).pack(
            padx=20,
            pady=15
        )

        # -------------------------------------------------
        # Close
        # -------------------------------------------------

        ttk.Button(
            dashboard,
            text="Close",
            command=dashboard.destroy
        ).pack(
            pady=15
        )


    # =====================================================
    # DELETE ACCOUNT
    # =====================================================

    def delete_password(self):

        selected = (
            self.password_table.selection()
        )

        if not selected:

            messagebox.showwarning(
                "No Selection",
                "Please select an account."
            )

            return

        record = self.password_table.item(
            selected[0]
        )

        password_id = record["values"][0]

        confirmation = messagebox.askyesno(
            "Confirm Delete",
            "Are you sure you want to delete "
            "this account?"
        )

        if not confirmation:

            return

        try:

            connection = sqlite3.connect(
                DATABASE_NAME
            )

            cursor = connection.cursor()

            cursor.execute(
                """
                DELETE FROM passwords
                WHERE id = ?
                """,
                (password_id,)
            )

            connection.commit()

            connection.close()

        except sqlite3.Error as error:

            messagebox.showerror(
                "Database Error",
                f"Could not delete account:\n{error}"
            )

            return

        self.load_passwords()

        self.clear_fields()

        messagebox.showinfo(
            "Deleted",
            "Account deleted successfully."
        )


    # =====================================================
    # CLEAR FIELDS
    # =====================================================

    def clear_fields(self):

        self.website_entry.delete(
            0,
            tk.END
        )

        self.username_entry.delete(
            0,
            tk.END
        )

        self.password_entry.delete(
            0,
            tk.END
        )

        self.notes_entry.delete(
            0,
            tk.END
        )

        self.category_box.set(
            "Other"
        )

        self.password_entry.config(
            show="*"
        )

        self.show_password_button.config(
            text="Show"
        )

        self.password_visible = False

        self.strength_label.config(
            text="Strength: -"
        )


    # =====================================================
    # LOCK VAULT
    # =====================================================

    def lock_vault(self):
        """
        Lock the vault and remove sensitive information
        from the application's active state.
        """

        # Remove encryption object.
        self.cipher = None

        # Cancel clipboard timer.
        if self.clipboard_clear_job is not None:

            try:

                self.root.after_cancel(
                    self.clipboard_clear_job
                )

            except Exception:

                pass

            self.clipboard_clear_job = None

        # Clear clipboard immediately.
        self.clear_clipboard()

        # Return to login screen.
        self.show_login()


# =========================================================
# 12. PROGRAM START
# =========================================================

if __name__ == "__main__":

    # Create database.
    create_database()

    # Create Tkinter application.
    root = tk.Tk()

    # Create application object.
    app = PasswordManager(
        root
    )

    # Start event loop.
    root.mainloop()