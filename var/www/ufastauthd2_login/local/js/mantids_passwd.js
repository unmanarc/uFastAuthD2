function checkPasswordReq(password, minsize) {
    var ret = "";

    var exprSpecial = /[!|\.|@|#|$|%|^|&|*|(|)|-|_]/;
    var exprNumber = /[0-9]/;
    var exprUpperCase = /[A-Z]/;
    var exprLowerCase = /[a-z]/;


    if (password.length < minsize) {
        ret = "The password should have at leat " + minsize + " characters";
    }
    else {
        var upperCharsCount = 0;
        var lowerCharsCount = 0;
        var numberCharsCount = 0;
        var specialCharsCount = 0;
    
        for (var i = 0; i < password.length; i++) {
            if (exprSpecial.test(password[i]))
                specialCharsCount++;
            else if (exprUpperCase.test(password[i]))
                upperCharsCount++;
            else if (exprLowerCase.test(password[i]))
                lowerCharsCount++;
            else if (exprNumber.test(password[i]))
                numberCharsCount++;
        }

        if (!upperCharsCount || !lowerCharsCount || !numberCharsCount || !specialCharsCount) {
            ret = "The new password is missing at least: ";
            if (!upperCharsCount)
                ret += "1 upper character,";
            if (!lowerCharsCount)
                ret += "1 lower character,";
            if (!numberCharsCount)
                ret += "1 number character,";
            if (!specialCharsCount)
                ret += "1 special character,";
        }
    }

    return ret;
}

function genNewPassword() {
    var passwordLength = 12;
    var passwordCharset = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ023456789.!@#$%*(){}[]";
    var password = "";

    var pwdCheck = "FALSE";

    while (  pwdCheck != "" )
    {
        password = "";
        for (var i = 0, n = passwordCharset.length; i < passwordLength; ++i) 
        {
            password += passwordCharset.charAt(Math.floor(Math.random() * n));
        }
        pwdCheck = checkPasswordReq(password,passwordLength);
    }

    return password;
}

function genNewKey() {
    var passwordLength = 32;
    var passwordCharset = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ023456789.!@#$%*";
    var password = "";

    var pwdCheck = "FALSE";

    while (  pwdCheck != "" )
    {
        password = "";
        for (var i = 0, n = passwordCharset.length; i < passwordLength; ++i) 
        {
            password += passwordCharset.charAt(Math.floor(Math.random() * n));
        }
        pwdCheck = checkPasswordReq(password,passwordLength);
    }

    return password;
}
