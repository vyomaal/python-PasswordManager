// =====================================================
// Secure Password Manager
// Chrome Background Service Worker
// =====================================================

const HOST_NAME =
    "com.securepasswordmanager.host";


// =====================================================
// MESSAGES FROM POPUP
// =====================================================

chrome.runtime.onMessage.addListener(
    function (message, sender, sendResponse) {

        // -------------------------------------------------
        // CONNECT
        // -------------------------------------------------

        if (message.action === "connect") {

            connectToPython(
                {
                    action: "ping"
                },
                sendResponse
            );

            return true;
        }


        // -------------------------------------------------
        // GET ACCOUNTS
        // -------------------------------------------------

        if (message.action === "get_accounts") {

            connectToPython(
                {
                    action: "get_accounts"
                },
                sendResponse
            );

            return true;
        }


        // -------------------------------------------------
        // SEARCH ACCOUNTS
        // -------------------------------------------------

        if (message.action === "search_accounts") {

            connectToPython(
                {
                    action: "search_accounts",
                    search: message.search || ""
                },
                sendResponse
            );

            return true;
        }


        // -------------------------------------------------
        // GET PASSWORD
        // -------------------------------------------------

        if (message.action === "get_password") {

            connectToPython(
                {
                    action: "get_password",
                    account_id: message.account_id,
                    master_password: message.master_password
                },
                sendResponse
            );

            return true;
        }


        // -------------------------------------------------
        // FILL LOGIN
        // -------------------------------------------------

        if (message.action === "fill_login") {

            fillLogin(
                message.username,
                message.password,
                sendResponse
            );

            return true;
        }
    }
);


// =====================================================
// CONNECT TO PYTHON
// =====================================================

function connectToPython(
    message,
    sendResponse
) {

    let port;

    try {

        port =
            chrome.runtime.connectNative(
                HOST_NAME
            );

    } catch (error) {

        sendResponse({
            success: false,
            message:
                "Could not start Python host: " +
                error.message
        });

        return;
    }


    // -------------------------------------------------
    // Receive Python response
    // -------------------------------------------------

    port.onMessage.addListener(
        function (response) {

            sendResponse(
                response
            );

            port.disconnect();
        }
    );


    // -------------------------------------------------
    // Handle connection error
    // -------------------------------------------------

    port.onDisconnect.addListener(
        function () {

            if (
                chrome.runtime.lastError
            ) {

                sendResponse({

                    success: false,

                    message:
                        chrome.runtime.lastError.message

                });
            }
        }
    );


    // -------------------------------------------------
    // Send request to Python
    // -------------------------------------------------

    port.postMessage(
        message
    );
}


// =====================================================
// FILL LOGIN FORM
// =====================================================

async function fillLogin(
    username,
    password,
    sendResponse
) {

    try {

        // Find the currently active browser tab.
        const tabs =
            await chrome.tabs.query({
                active: true,
                currentWindow: true
            });


        if (
            !tabs ||
            tabs.length === 0
        ) {

            sendResponse({

                success: false,

                message:
                    "No active browser tab found."

            });

            return;
        }


        const tab =
            tabs[0];


        // -------------------------------------------------
        // Do not inject into Chrome internal pages.
        // -------------------------------------------------

        if (
            !tab.url ||
            tab.url.startsWith(
                "chrome://"
            ) ||
            tab.url.startsWith(
                "chrome-extension://"
            ) ||
            tab.url.startsWith(
                "edge://"
            )
        ) {

            sendResponse({

                success: false,

                message:
                    "Cannot autofill this browser page."

            });

            return;
        }


        // -------------------------------------------------
        // Execute the autofill code in the webpage.
        // -------------------------------------------------

        await chrome.scripting.executeScript({

            target: {
                tabId: tab.id
            },

            args: [
                username,
                password
            ],

            func: (
                usernameValue,
                passwordValue
            ) => {

                // Find possible username fields.
                const usernameSelectors = [
                    'input[type="email"]',
                    'input[type="text"]',
                    'input[name*="user" i]',
                    'input[name*="login" i]',
                    'input[id*="user" i]',
                    'input[id*="login" i]'
                ];


                // Find possible password fields.
                const passwordSelectors = [
                    'input[type="password"]',
                    'input[name*="pass" i]',
                    'input[id*="pass" i]'
                ];


                // Find username field.
                let usernameField = null;

                for (
                    const selector
                    of usernameSelectors
                ) {

                    usernameField =
                        document.querySelector(
                            selector
                        );

                    if (
                        usernameField
                    ) {

                        break;
                    }
                }


                // Find password field.
                let passwordField = null;

                for (
                    const selector
                    of passwordSelectors
                ) {

                    passwordField =
                        document.querySelector(
                            selector
                        );

                    if (
                        passwordField
                    ) {

                        break;
                    }
                }


                // -----------------------------------------
                // Fill username.
                // -----------------------------------------

                if (
                    usernameField
                ) {

                    usernameField.focus();

                    usernameField.value =
                        usernameValue;

                    usernameField.dispatchEvent(
                        new Event(
                            "input",
                            {
                                bubbles: true
                            }
                        )
                    );

                    usernameField.dispatchEvent(
                        new Event(
                            "change",
                            {
                                bubbles: true
                            }
                        )
                    );
                }


                // -----------------------------------------
                // Fill password.
                // -----------------------------------------

                if (
                    passwordField
                ) {

                    passwordField.focus();

                    passwordField.value =
                        passwordValue;

                    passwordField.dispatchEvent(
                        new Event(
                            "input",
                            {
                                bubbles: true
                            }
                        )
                    );

                    passwordField.dispatchEvent(
                        new Event(
                            "change",
                            {
                                bubbles: true
                            }
                        )
                    );
                }


                return {

                    usernameFound:
                        Boolean(
                            usernameField
                        ),

                    passwordFound:
                        Boolean(
                            passwordField
                        )
                };
            }

        }).then(
            function (results) {

                const result =
                    results[0]?.result;


                if (!result) {

                    sendResponse({

                        success: false,

                        message:
                            "Could not fill the login form."

                    });

                    return;
                }


                if (
                    !result.usernameFound &&
                    !result.passwordFound
                ) {

                    sendResponse({

                        success: false,

                        message:
                            "No username or password fields were found."

                    });

                    return;
                }


                sendResponse({

                    success: true,

                    message:
                        "Login information filled."

                });
            }
        );

    } catch (error) {

        sendResponse({

            success: false,

            message:
                "Autofill failed: " +
                error.message

        });
    }
}