
let loggedIn = false;
let loggedInParamx = true;

function logout() {
    $.ajax({
        url: "/api/v1/logout",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({}),
        success: function (response) {
            console.log("Logout success:", response);
            // Recargar la página con los mismos parámetros GET
            loggedIn = false;
            //alert("logged out");
            location.href = window.location.href;
        },
        error: function (xhr, status, error) {
            console.error("Error during logout:", status, error);
            console.log(status);
            // Set message:
            $('#message').text(`${error}: ${xhr.responseJSON["message"]}`);
        }
    });
}

function reloadTokenAndRedirect() 
{
    // Retrieve the 'redirectURI' and 'app' parameter from the URL
    const urlParams = new URLSearchParams(window.location.search);
    const encodedRedirectURI = urlParams.get('redirectURI');
    const appName = urlParams.get('app');
    const mode = urlParams.get('mode');

    // Decode the base64 parameter
    let decodedRedirectURI = "";
    try {
        decodedRedirectURI = atob(encodedRedirectURI);
    } catch (error) {
        console.error("Error decoding redirectURI parameter:", error);
        $('#message').text("Invalid redirect URI");
        return;
    }

    // Perform the AJAX request
    $.ajax({
        url: "/api/v1/retokenize",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({ redirectURI: decodedRedirectURI }),
        success: function (response) {
            console.log("App Token Adquired:", response);

            // Perform redirection via POST
            const form = document.createElement('form');

            if (mode === 'app') 
            {
                form.method = "GET";
            }
            else
            {
                form.method = "POST";
            }
            form.action = response.callbackURI;

            // Include the accessToken in the POST body
            const input = document.createElement('input');
            input.type = "hidden";
            input.name = "accessToken";
            input.value = response.accessToken;

            const input2 = document.createElement('input2');
            input2.type = "hidden";
            input2.name = "expiresIn";
            input2.value = response.expiresIn;

            const input3 = document.createElement('input3');
            input3.type = "hidden";
            input3.name = "redirectURI";
            input3.value = decodedRedirectURI;

            form.appendChild(input);
            form.appendChild(input2);
            form.appendChild(input3);
            document.body.appendChild(form);
            form.submit();
        },
        error: function (xhr, status, error) {
            console.error("Error during authorization:", status, error);

            // Set error message
            $('#message').text(`${error}: ${xhr.responseJSON["message"]}`);
        }
    });
}

function redirectToAuthenticatedSite() {

    if (loggedInParamx === false)
    {
        // Reinject the application token.
        reloadTokenAndRedirect();
        return;
    }


    // Retrieve the 'redirectURI' and 'app' parameter from the URL
    const urlParams = new URLSearchParams(window.location.search);
    const encodedRedirectURI = urlParams.get('redirectURI');
    const appName = urlParams.get('app');
    const mode = urlParams.get('mode');

    // Decode the base64 parameter
    let decodedRedirectURI = "";
    try {
        decodedRedirectURI = atob(encodedRedirectURI);
    } catch (error) {
        console.error("Error decoding redirectURI parameter:", error);
        $('#message').text("Invalid redirect URI");
        return;
    }

    // Perform the AJAX request
    $.ajax({
        url: "/api/v1/getApplicationAuthCallbackURI",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({ 
            app: appName,
            redirectURI: decodedRedirectURI 
        }),
        success: function (response) {
            console.log("App Token Adquired:", response);

            // Perform redirection via POST
            const form = document.createElement('form');

            if (mode === 'app') 
            {
                form.method = "GET";
            }
            else
            {
                form.method = "POST";
            }
            form.action = response.callbackURI;

            // Include the accessToken in the POST body
            const input = document.createElement('input');
            input.type = "hidden";
            input.name = "accessToken";
            input.value = ""; // Keep the current/used access token.

            const input3 = document.createElement('input3');
            input3.type = "hidden";
            input3.name = "redirectURI";
            input3.value = decodedRedirectURI;

            form.appendChild(input);
            form.appendChild(input3);

            document.body.appendChild(form);
            form.submit();
        },
        error: function (xhr, status, error) {
            console.error("Error during authorization:", status, error);

            // Set error message
            $('#message').text(`${error}: ${xhr.responseJSON["message"]}`);
        }
    });
}

$(document).ready(function () {
    let currentSlotIndex = 0;
    let schemes = [];

    $("#version").text(softwareVersion);

    // Focus on username input when the page loads
    $("#username").focus();

    $("#message").text('Please enter your username');

    // Validate if 'redirectURI' exists and is a valid base64 string
    const urlParams = new URLSearchParams(window.location.search);
    const encodedRedirectURI = urlParams.get('redirectURI');
    const appName = urlParams.get('app');
    const loggedInParam = urlParams.get('loggedIn');

    if (loggedInParam === "false")
    {
        // Remove the 'loggedIn' parameter from the URL
        const newUrlSearchParams = new URLSearchParams(window.location.search);
        newUrlSearchParams.delete('loggedIn');
        window.history.replaceState(null, '', `${window.location.pathname}?${newUrlSearchParams.toString()}${window.location.hash}`);
        loggedInParamx = false;
    }

  /*  
    now permit empty redirect URI.
    if (!encodedRedirectURI) 
    {
        console.log('invalid redirectURI parameter.');
        console.log(urlParams);
        console.log(window.location.search);
        console.log(encodedRedirectURI);

        $('#message').text("Invalid redirect URI...");
        $("#usernameForm").addClass("d-none");
        return;
    }*/

    if (!appName)
    {
        console.log('invalid app');
        console.log(urlParams);
        console.log(window.location.search);
        console.log(encodedRedirectURI);

        $('#message').text("Invalid Application Name...");
        $("#usernameForm").addClass("d-none");
        return;
    }

    try {
        atob(encodedRedirectURI); // Test decoding to ensure valid base64
    } catch (error) {
        console.error("Error decoding redirectURI parameter:", error);
        $('#message').text("Invalid redirect URI...");
        $("#usernameForm").addClass("d-none");
        return;
    }

    // Load refresh token from cookie
    const cookies = document.cookie.split(';');
    cookies.forEach(cookie => {
        const [name, value] = cookie.trim().split('=');

        if (name === 'loggedIn')
        {
            loggedIn = true;

            $("#usernameForm").addClass("d-none");
            $("#logoutForm").removeClass("d-none");
            $("#message").text('Already logged in');

        }
    });

    // Function to initialize authentication flow using preAuthorize API
    function initializeAuthentication(username) {
        const appName = urlParams.get('app');
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
                    alert("No available authentication scheme found.");
                    return;
                }

                schemes = scheme.slots;
                $("#schemeDescription").text(scheme.description).css("font-weight", "bold");

                showNextSlot();
            },
            error: function (xhr, status, error) {
                console.error("Error calling preAuthorize API:", status, error);
                alert("Failed to initiate authentication. Please try again.");
            }
        });
    }



    function loadTokenAndRedirect() {
        // Retrieve the 'redirectURI' and 'app' parameter from the URL
        const urlParams = new URLSearchParams(window.location.search);
        const encodedRedirectURI = urlParams.get('redirectURI');
        const appName = urlParams.get('app');
        const mode = urlParams.get('mode');
    
        // Decode the base64 parameter
        let decodedRedirectURI = "";
        try {
            decodedRedirectURI = atob(encodedRedirectURI);
        } catch (error) {
            console.error("Error decoding redirectURI parameter:", error);
            $('#message').text("Invalid redirect URI");
            return;
        }
    
        // Perform the AJAX request
        $.ajax({
            url: "/api/v1/token",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({ redirectURI: decodedRedirectURI }),
            success: function (response) {
                console.log("App Token Adquired:", response);
    /*
                // Prepare JSON payload for POST body
                const payload = {
                    access_token: response.accessToken,
                    expiresIn: response.expiresIn,
                    app_name: appName,
    
                    token_type: "Bearer"
                };*/
    
                // Perform redirection via POST
                const form = document.createElement('form');
    
                if (mode === 'app') 
                {
                    form.method = "GET";
                }
                else
                {
                    form.method = "POST";
                }
                form.action = response.callbackURI;
    
                // Include the accessToken in the POST body
                const input = document.createElement('input');
                input.type = "hidden";
                input.name = "accessToken";
                input.value = response.accessToken;
    
                const input2 = document.createElement('input2');
                input2.type = "hidden";
                input2.name = "expiresIn";
                input2.value = response.expiresIn;
    
                const input3 = document.createElement('input3');
                input3.type = "hidden";
                input3.name = "redirectURI";
                input3.value = decodedRedirectURI;
    
                form.appendChild(input);
                form.appendChild(input2);
                form.appendChild(input3);
                document.body.appendChild(form);
                form.submit();
            // alert("ok, ya");
            },
            error: function (xhr, status, error) {
                console.error("Error during authorization:", status, error);
    
                // Set error message
                $('#message').text(`${error}: ${xhr.responseJSON["message"]}`);
            }
        });
    }


    // Function to send authorization request for each slot
    function authorizeUser(username, schemeId, password) {
        const appName = urlParams.get('app');

        $.ajax({
            url: "/api/v1/authorize",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({
                preAuthUser: username,
                applicationName: appName,
                schemeId: schemeId,
                password: password,
                authMode: "MODE_PLAIN",
                challengeSalt: ""
            }),
            success: function (response) {
                console.log("Authorization success:", response);

                if (response.isFullyAuthenticated) {
                    loggedIn = true;
                    $("#message").text("Authenticated! Redirecting...");
                    loadTokenAndRedirect();
                } else {
                    currentSlotIndex++;
                    showNextSlot();
                }
            },
            error: function (xhr, status, error) {
                console.error("Error during authorization:", status, error);
                console.log(status);
                loggedIn = false;
                // Set message:
                //console.log(`${error}: ${xhr.responseJSON["message"]}`);
                $('#message').text(`${error}: ${xhr.responseJSON["message"]}`);
            }
        });
    }

    // Update the content based on the current slot
    function showNextSlot() {
        if (currentSlotIndex >= schemes.length) {
            $("#message").text("Authenticated! Redirecting...");
            loadTokenAndRedirect();
            // Here we have to get the application token
            return;
        }

        const slot = schemes[currentSlotIndex];
        const { description, passwordFunction } = slot.details;

        $("#message").text("Please enter your " + description);

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
