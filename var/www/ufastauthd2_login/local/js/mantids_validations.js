function checkAppName() {
    var regex = new RegExp("^[a-zA-Z0-9_-]+$");
    var key = String.fromCharCode(!event.charCode ? event.which : event.charCode);
    if (!regex.test(key)) {
        event.preventDefault();
        return false;
    }
    return true;
}


function checkUserName() {
    var regex = new RegExp("^[a-zA-Z0-9_-]+$");
    var key = String.fromCharCode(!event.charCode ? event.which : event.charCode);
    if (!regex.test(key)) {
        event.preventDefault();
        return false;
    }
    return true;
}