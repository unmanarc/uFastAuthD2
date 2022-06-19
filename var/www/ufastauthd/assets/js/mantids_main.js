function logoutOK(response) {
  window.location = "/login";
}
function logoutFAILED(response) {
  console.log("Your sessionId is not working anymore in the remote side");
  window.location = "/login";
}
function logout() {
  $.ajax({
    url: '/japi_session?mode=LOGOUT',
    type: 'POST',
    headers: { "CSRFToken": csrfToken },
    success: logoutOK,
    error: logoutFAILED
  });
}

function commonFunctionError(xhr, ajaxOptions, thrownError) {
  if (xhr.status == 404) {
    // Session is gone...
    alert("Unauthorized Function");
    logout();
  }
  else {
    console.log("Network error " + xhr.status);
  }
}

var intervalId = -1;

function ajaxAuthReCheck() 
{
  $.ajax({
    url: '/japi_session?mode=AUTHINFO',
    headers: { "CSRFToken": csrfToken },
    type: 'POST',
    success: function (response)
    {
      // Reestablish the interval with the new maxAge.
      clearInterval(intervalId);
      var intTime = parseInt(response["maxAge"],10)+1;
      console.log("Setting up the next session check to " + intTime + " sec's in future.");
      intervalId = setInterval(ajaxAuthReCheck, (intTime)*1000);
      console.log("Session renewed: " + response["maxAge"] + " sec's left" );
    },
    error: function (xhr, ajaxOptions, thrownError) {
      if(xhr.status==404) 
      {
        // Session is gone...
        clearInterval(intervalId);
        alert("Session Expired");
        logout();
      }
      else
      {
        console.log("Network error " + xhr.status);
      }
    }
  });
}

function ajaxLoadInfo() {
 $('#welcome').text("Welcome " + user);
 $("#version").text(softwareVersion);

  // Check the authentication when the session is supposed to expire, and logout if there is no session.
  var intTime = maxAge+1;
  console.log("Setting up the next session check to " + intTime + " sec's in future.");
  intervalId = setInterval(ajaxAuthReCheck,intTime*1000);

  csrfReady();
}

function ajaxRemoteExecuteMethod( methodPermLevel, target, methodName, payload, successFunction  ) {
  var method = "remote." + methodPermLevel;
  var payloadData = { "target": target, "remoteMethod": methodPermLevel + "." + methodName, "payload" : payload }
  $.ajax({
    url: '/japi_exec?method=' + method,
    type: 'POST',
    headers: { "CSRFToken": csrfToken },
    data: { payload: JSON.stringify(payloadData) },
    success: successFunction,
    error: function (result) {
      console.log("ERR");
      alert("Error Executing Remote Method...\nInsufficient Permissions");
    }
  });
}

function ajaxExecuteMethod( methodName, payloadData, successFunction ) {
  $.ajax({
    url: '/japi_exec?method=' + methodName,
    type: 'POST',
    headers: { "CSRFToken": csrfToken },
    data: { payload: JSON.stringify(payloadData) },
    success: successFunction,
    error: function (result) {
      console.log("ERR");
      alert("Error Executing Remote Method...\nInsufficient Permissions");
    }
  });
}
