/**
 * This script manages session timeout and automatic token refresh for a web application.
 *
 * It uses the following variables:
 * 
 * - maxAge: Holds the maximum age of the session in seconds, updated from server response.
 * - sessionTimeout: Stores the ID of the setTimeout function used to manage session countdown.
 */

//<%jvar/maxAge:maxAge%>//
//<%jvar/user:user%>//
//<%jvar/domain:domain%>//

let maxAgeVar = maxAge;
let sessionTimeout = null;

function updateSessionFailed() {
  alert("Session Update Failed");
}

/**
 * Sends an AJAX request to the server to refresh the access token.
 * Upon successful response, it updates maxAgeVar and restarts the session timer.
 */
function refreshAccessToken() {
  $.ajax({
    url: '/auth/api/v1/refreshAccessToken',
    type: 'POST',
    success: function (response) {
      // Update maxAgeVar with the new value from server
      maxAgeVar = response["maxAge"];

      // Start or restart the session timer based on the new maxAgeVar value
      startAccessRetokenizerTimer();
    },
    error: updateSessionFailed
  });
}

function logout() {
  $.ajax({
    url: '/auth/api/v1/logout',
    type: 'POST',
    success: function (response) {
      // Redirect to the login page or reload the current page after logout
      window.location.reload();
    },
    error: function () {
      alert('Logout failed');
    }
  });
}

/**
 * Starts a countdown timer for the session.
 * When the countdown reaches zero, it triggers an AJAX request to refresh the access token.
 */
function startAccessRetokenizerTimer() {
  // Countdown is set to 10 seconds before maxAgeVar to ensure timely token refresh
  const countdown = maxAgeVar - 10;

  if (countdown > 0) {
    // Clear any existing timeout to avoid multiple timers running simultaneously
    clearTimeout(sessionTimeout);

    // Set a new timeout for session expiration and automatic renewal
    sessionTimeout = setTimeout(() => {
      refreshAccessToken();
    }, countdown * 1000);
  }
}

// Initialize the session timer when the script loads, starting the countdown
startAccessRetokenizerTimer();

