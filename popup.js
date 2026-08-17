// =====================================================
// Secure Password Manager - Browser Extension
// popup.js
// =====================================================


// =====================================================
// GET HTML ELEMENTS
// =====================================================

const connectButton =
    document.getElementById("connectButton");

const loadAccountsButton =
    document.getElementById("loadAccountsButton");

const generateButton =
    document.getElementById("generateButton");

const statusText =
    document.getElementById("status");

const searchInput =
    document.getElementById("search");

const accountsContainer =
    document.getElementById("accounts");

const generatedPassword =
    document.getElementById("generatedPassword");


// =====================================================
// CONNECT TO PYTHON
// =====================================================

connectButton.addEventListener(
    "click",
    function () {

        statusText.textContent =
            "Connecting...";

        chrome.runtime.sendMessage(
            {
                action: "connect"
            },
            function (response) {

                if (chrome.runtime.lastError) {

                    statusText.textContent =
                        "Connection failed: " +
                        chrome.runtime.lastError.message;

                    return;
                }

                if (!response) {

                    statusText.textContent =
                        "No response from Python.";

                    return;
                }

                if (response.success) {

                    statusText.textContent =
                        response.message;

                } else {

                    statusText.textContent =
                        "Connection failed: " +
                        response.message;
                }
            }
        );
    }
);


// =====================================================
// LOAD ALL ACCOUNTS
// =====================================================

loadAccountsButton.addEventListener(
    "click",
    function () {

        loadAccounts();
    }
);


// =====================================================
// SEARCH ACCOUNTS
// =====================================================

searchInput.addEventListener(
    "input",
    function () {

        const searchTerm =
            searchInput.value.trim();

        if (!searchTerm) {

            loadAccounts();

            return;
        }

        searchAccounts(
            searchTerm
        );
    }
);


// =====================================================
// LOAD ACCOUNTS
// =====================================================

function loadAccounts() {

    statusText.textContent =
        "Loading accounts...";

    chrome.runtime.sendMessage(
        {
            action: "get_accounts"
        },
        function (response) {

            if (chrome.runtime.lastError) {

                statusText.textContent =
                    "Error: " +
                    chrome.runtime.lastError.message;

                return;
            }

            if (!response) {

                statusText.textContent =
                    "No response from Python.";

                return;
            }

            if (!response.success) {

                statusText.textContent =
                    "Error: " +
                    response.message;

                return;
            }

            statusText.textContent =
                "Accounts loaded.";

            displayAccounts(
                response.accounts
            );
        }
    );
}


// =====================================================
// SEARCH ACCOUNTS
// =====================================================

function searchAccounts(
    searchTerm
) {

    statusText.textContent =
        "Searching...";

    chrome.runtime.sendMessage(
        {
            action: "search_accounts",
            search: searchTerm
        },
        function (response) {

            if (chrome.runtime.lastError) {

                statusText.textContent =
                    "Search error: " +
                    chrome.runtime.lastError.message;

                return;
            }

            if (!response) {

                statusText.textContent =
                    "No response from Python.";

                return;
            }

            if (!response.success) {

                statusText.textContent =
                    "Search error: " +
                    response.message;

                return;
            }

            statusText.textContent =
                "Search complete.";

            displayAccounts(
                response.accounts
            );
        }
    );
}


// =====================================================
// DISPLAY ACCOUNTS
// =====================================================

function displayAccounts(
    accounts
) {

    // Remove old results.
    accountsContainer.innerHTML = "";


    // No accounts found.
    if (
        !accounts ||
        accounts.length === 0
    ) {

        accountsContainer.innerHTML =
            "<p>No accounts found.</p>";

        return;
    }


    // Create one card per account.
    accounts.forEach(
        function (account) {

            const accountDiv =
                document.createElement("div");

            accountDiv.className =
                "account";


            // -------------------------------------------------
            // Website
            // -------------------------------------------------

            const website =
                document.createElement("div");

            website.className =
                "website";

            website.textContent =
                account.website;


            // -------------------------------------------------
            // Username
            // -------------------------------------------------

            const username =
                document.createElement("div");

            username.className =
                "username";

            username.textContent =
                "Username: " +
                account.username;


            // -------------------------------------------------
            // Category
            // -------------------------------------------------

            const category =
                document.createElement("div");

            category.className =
                "category";

            category.textContent =
                "Category: " +
                account.category;


            // -------------------------------------------------
            // Show Password button
            // -------------------------------------------------

            const showPasswordButton =
                document.createElement("button");

            showPasswordButton.textContent =
                "🔐 Show Password";


            showPasswordButton.addEventListener(
                "click",
                function () {

                    requestPassword(
                        account.id,
                        accountDiv,
                        showPasswordButton
                    );
                }
            );


            // -------------------------------------------------
            // Add everything to account card.
            // -------------------------------------------------

            accountDiv.appendChild(
                website
            );

            accountDiv.appendChild(
                username
            );

            accountDiv.appendChild(
                category
            );

            accountDiv.appendChild(
                document.createElement("br")
            );

            accountDiv.appendChild(
                showPasswordButton
            );


            // Add card to account list.
            accountsContainer.appendChild(
                accountDiv
            );
        }
    );
}


// =====================================================
// REQUEST PASSWORD
// =====================================================

function requestPassword(
    accountId,
    accountDiv,
    showPasswordButton
) {

    // Ask for the master password.
    const masterPassword =
        window.prompt(
            "Enter your master password:"
        );


    // User cancelled.
    if (masterPassword === null) {

        return;
    }


    // Empty password.
    if (!masterPassword) {

        alert(
            "Master password is required."
        );

        return;
    }


    showPasswordButton.disabled =
        true;

    showPasswordButton.textContent =
        "Checking...";


    // Send password request to Python.
    chrome.runtime.sendMessage(
        {
            action: "get_password",

            account_id: accountId,

            master_password:
                masterPassword
        },
        function (response) {

            // Clear the local reference.
            // The request has already been sent.
            // This prevents unnecessary retention.
            // Note: JavaScript strings cannot be
            // manually zeroed from memory.
            
            if (chrome.runtime.lastError) {

                showPasswordButton.disabled =
                    false;

                showPasswordButton.textContent =
                    "🔐 Show Password";

                alert(
                    "Connection error: " +
                    chrome.runtime.lastError.message
                );

                return;
            }


            if (!response) {

                showPasswordButton.disabled =
                    false;

                showPasswordButton.textContent =
                    "🔐 Show Password";

                alert(
                    "No response from Python."
                );

                return;
            }


            if (!response.success) {

                showPasswordButton.disabled =
                    false;

                showPasswordButton.textContent =
                    "🔐 Show Password";

                alert(
                    response.message
                );

                return;
            }


            // Password was successfully decrypted.
            displayPassword(
                response.account.password,
                accountDiv,
                showPasswordButton
            );
        }
    );
}


// =====================================================
// DISPLAY PASSWORD
// =====================================================

function displayPassword(
    password,
    accountDiv,
    showPasswordButton
) {

    // Remove an existing password area.
    const oldPassword =
        accountDiv.querySelector(
            ".password-area"
        );

    if (oldPassword) {

        oldPassword.remove();
    }


    // Create password container.
    const passwordArea =
        document.createElement("div");

    passwordArea.className =
        "password-area";


    // Password input.
    const passwordInput =
        document.createElement("input");

    passwordInput.type =
        "text";

    passwordInput.value =
        password;

    passwordInput.readOnly =
        true;

    passwordInput.style.width =
        "100%";

    passwordInput.style.boxSizing =
        "border-box";

    passwordInput.style.marginTop =
        "6px";


    // Copy button.
    const copyButton =
        document.createElement("button");

    copyButton.textContent =
        "📋 Copy";


    copyButton.addEventListener(
        "click",
        async function () {

            try {

                await navigator.clipboard.writeText(
                    password
                );

                copyButton.textContent =
                    "✓ Copied!";

                // Clear clipboard after 30 seconds.
                setTimeout(
                    async function () {

                        try {

                            await navigator.clipboard.writeText(
                                ""
                            );

                        } catch (error) {

                            // Clipboard clearing may fail
                            // if browser permissions change.
                        }

                    },
                    30000
                );

            } catch (error) {

                alert(
                    "Could not copy password."
                );
            }
        }
    );


    // Hide button.
    const hideButton =
        document.createElement("button");

    hideButton.textContent =
        "🙈 Hide";


    hideButton.addEventListener(
        "click",
        function () {

            passwordArea.remove();

            showPasswordButton.disabled =
                false;

            showPasswordButton.textContent =
                "🔐 Show Password";
        }
    );

    // =====================================================
// FILL LOGIN BUTTON
// =====================================================

const fillButton =
    document.createElement("button");

fillButton.textContent =
    "📝 Fill Login";


fillButton.addEventListener(
    "click",
    function () {

        fillButton.disabled =
            true;

        fillButton.textContent =
            "Filling...";


        chrome.runtime.sendMessage(
            {
                action: "fill_login",

                username:
                    response.account.username,

                password:
                    password
            },
            function (response) {

                fillButton.disabled =
                    false;

                fillButton.textContent =
                    "📝 Fill Login";


                if (
                    chrome.runtime.lastError
                ) {

                    alert(
                        "Autofill error: " +
                        chrome.runtime.lastError.message
                    );

                    return;
                }


                if (!response) {

                    alert(
                        "No response from browser."
                    );

                    return;
                }


                if (!response.success) {

                    alert(
                        response.message
                    );

                    return;
                }


                statusText.textContent =
                    "Login information filled.";
            }
        );
    }
);


    // Add password controls.
    passwordArea.appendChild(
        passwordInput
    );

    passwordArea.appendChild(
        copyButton
    );

    passwordArea.appendChild(
    hideButton
    );

    passwordArea.appendChild(
    fillButton
    );


    accountDiv.appendChild(
        passwordArea
    );


    showPasswordButton.disabled =
        true;

    showPasswordButton.textContent =
        "✓ Password Shown";


    // -----------------------------------------------------
    // Automatically hide after 30 seconds.
    // -----------------------------------------------------

    setTimeout(
        function () {

            if (
                passwordArea.parentNode
            ) {

                passwordArea.remove();
            }

            showPasswordButton.disabled =
                false;

            showPasswordButton.textContent =
                "🔐 Show Password";

        },
        30000
    );
}


// =====================================================
// PASSWORD GENERATOR
// =====================================================

generateButton.addEventListener(
    "click",
    function () {

        const lowercase =
            "abcdefghijklmnopqrstuvwxyz";

        const uppercase =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        const numbers =
            "0123456789";

        const symbols =
            "!@#$%^&*()_+-=[]{}";

        const allCharacters =
            lowercase +
            uppercase +
            numbers +
            symbols;

        let password = "";


        // Guarantee lowercase.
        password += randomCharacter(
            lowercase
        );


        // Guarantee uppercase.
        password += randomCharacter(
            uppercase
        );


        // Guarantee number.
        password += randomCharacter(
            numbers
        );


        // Guarantee symbol.
        password += randomCharacter(
            symbols
        );


        // Generate remaining characters.
        for (
            let i = 4;
            i < 16;
            i++
        ) {

            password += randomCharacter(
                allCharacters
            );
        }


        // Shuffle password.
        password =
            password
                .split("")
                .sort(
                    () => Math.random() - 0.5
                )
                .join("");


        generatedPassword.value =
            password;
    }
);


// =====================================================
// RANDOM CHARACTER
// =====================================================

function randomCharacter(
    characters
) {

    const index =
        Math.floor(
            Math.random() *
            characters.length
        );

    return characters[index];
}