// Helpers:

function updateMessage(text) {
    $("#message").text(text);
}

function showError(error) {
    updateMessage(`${error}`);
}

function showErrorWithDetails(error, message) {
    showError(`${error}: ${message}`);
}

function showErrorWithXHR(xhr, status, error) {
    showErrorWithDetails(error, xhr.responseJSON["message"]);
}


// Helper to create and submit form
function createAndSubmitRedirectForm(actionUrl, data, method = 'POST') {
    const form = document.createElement('form');
    form.method = method;
    form.action = actionUrl;
    Object.entries(data).forEach(([name, value]) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
}

////////////////////////////////////////////////////////////////////////////////////

let decodedRedirectURI = "";
let loggedIn = false;
let loggedInGETParsedParam = true;

const urlParams = new URLSearchParams(window.location.search);

// Retrieve the 'redirectURI' and 'app' parameter from the URL
const mode = urlParams.get('mode');
const appName = urlParams.get('app');
const encodedRedirectURI = urlParams.get('redirectURI');

function logout() {
    $.ajax({
        url: "/api/v1/logout",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({}),
        headers: {
            "X-Logout": "1" // This prevents CSRF logout attacks.
        },
        success: function (response) {
            // Recargar la página con los mismos parámetros GET
            loggedIn = false;
            location.reload();
        },
        error: showErrorWithXHR
    });
}

function loadTokenAndRedirect() {
    // Perform the AJAX request
    $.ajax({
        url: "/api/v1/token",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify(
            {
                redirectURI: decodedRedirectURI,
                schemeId: 1,
                activity: "LOGIN",
                app: appName

            }
        ),
        headers: {
            "X-Logout": "1" // This prevents CSRF logout attacks.
        },
        success: function (response) {
            // submit the token to the app.
            const callbackURI = response.callbackURI;
            createAndSubmitRedirectForm(callbackURI, response, mode === 'app' ? 'GET' : 'POST');
        },
        error: showErrorWithXHR
    });
}

$(document).ready(function () {
    let currentSlotIndex = 0;
    let schemes = [];

    $("#version").text(softwareVersion);

    // Focus on username input when the page loads
    $("#username").focus();

    updateMessage('Please enter your username');

    const loggedInGETParam = urlParams.get('loggedIn');

    if (loggedInGETParam === "false") {
        // Remove the 'loggedIn' parameter from the URL
        const newUrlSearchParams = new URLSearchParams(window.location.search);
        newUrlSearchParams.delete('loggedIn');
        window.history.replaceState(null, '', `${window.location.pathname}?${newUrlSearchParams.toString()}${window.location.hash}`);
        loggedInGETParsedParam = false;
    }

    if (!appName) {
        updateMessage('ERROR: Invalid Application Name.');
        $("#usernameForm").addClass("d-none");
        return;
    }

    // Validate if 'redirectURI' exists and is a valid base64 string
    if (!encodedRedirectURI) {
        decodedRedirectURI = "";
    } else {
        try {
            decodedRedirectURI = atob(encodedRedirectURI);
        } catch (error) {
            updateMessage('ERROR: Invalid redirect URI.');
            $("#usernameForm").addClass("d-none");
            return;
        }
    }

    // Load refresh token from cookie
    const cookies = document.cookie.split(';');
    cookies.forEach(cookie => {
        const [name, value] = cookie.trim().split('=');
        if (name === 'loggedIn') {
            loggedIn = true;

            $("#usernameForm").addClass("d-none");
            $("#logoutForm").removeClass("d-none");

            updateMessage('Already logged in.');
        }
    });

    // Function to initialize authentication flow using preAuthorize API
    function initializeAuthentication(username) {
        $.ajax({
            url: "/api/v1/preAuthorize",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({
                accountName: username,
                app: appName,
                activity: "LOGIN"
            }),
            success: function (response) {
                const defaultSchemeIndex = response.defaultScheme;
                const scheme = response.availableSchemes[defaultSchemeIndex];

                if (!scheme) {
                    updateMessage('ERROR: No available authentication scheme found.');
                    return;
                }

                schemes = scheme.slots;
                $("#schemeDescription").text(scheme.description).css("font-weight", "bold");

                showNextSlot();
            },
            error: showErrorWithXHR
        });
    }

    // Function to send authorization request for each slot
    function authorizeUser(username, schemeId, password) {
        $.ajax({
            url: "/api/v1/authorize",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({
                preAuthUser: username,
                keepAuthenticated: $("#keepAuthenticated").is(":checked"),
                app: appName,
                schemeId: schemeId,
                password: password,
                authMode: "MODE_PLAIN",
                challengeSalt: ""
            }),
            success: function (response) {
                console.log("Authorization success:", response);

                if (response.isFullyAuthenticated) {
                    loggedIn = true;
                    updateMessage("Authenticated! Redirecting...");
                    loadTokenAndRedirect();
                } else {
                    currentSlotIndex++;
                    showNextSlot();
                }
            },
            error: function (xhr, status, error) {
                showErrorWithXHR(xhr, status, error);
                loggedIn = false;
            }
        });
    }

    // Update the content based on the current slot
    function showNextSlot() {
        if (currentSlotIndex >= schemes.length) {
            updateMessage("Authenticated! Redirecting...");
            loadTokenAndRedirect();
            // Here we have to get the application token
            return;
        }

        const slot = schemes[currentSlotIndex];
        const { description, passwordFunction } = slot.details;

        updateMessage("Please enter your " + description);

        if (passwordFunction === 5) {
            // OTP input
            $("#genericInputForm").addClass("d-none");
            $("#otpForm").removeClass("d-none");
            $("#otp").focus();
        } else if ([1, 2].includes(passwordFunction)) {
            // Password input
            $("#otpForm").addClass("d-none");
            $("#genericInputForm").removeClass("d-none");
            $("#genericInput").focus();
        } else {
            alert("Password function not implemented.");
        }
    }

    // Event listener for username submission
    $("#usernameForm").on("submit", function (e) {
        e.preventDefault();
        const username = $("#username").val();
        $("#usernameForm").addClass("d-none");
        initializeAuthentication(username);
    });

    // Event listener for generic input submission
    $("#genericInputForm").on("submit", function (e) {
        e.preventDefault();
        const username = $("#username").val();
        const schemeId = 1;
        const password = $("#genericInput").val();

        authorizeUser(username, schemeId, password);
    });

    // Event listener for OTP submission
    $("#otpForm").on("submit", function (e) {
        e.preventDefault();
        const username = $("#username").val();
        const schemeId = 1;
        const otp = $("#otp").val();

        authorizeUser(username, schemeId, otp);
    });
});
