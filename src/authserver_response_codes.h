#ifndef AUTHSERVER_RESPONSE_CODES_H
#define AUTHSERVER_RESPONSE_CODES_H

// Define constant integer values for response status codes
#define GENERIC_SUCCESS                 0
#define GENERIC_ERROR                   100

#define REGISTRATION_SUCCESS            10
#define REGISTRATION_ERROR              110
#define REGISTRATION_USERNAME_IN_USE    111
#define REGISTRATION_EMAIL_IN_USE       112

#define AUTHENTICATION_SUCCESS          20
#define AUTHENTICATION_TOKEN_COOKIE     21
#define AUTHENTICATION_TOKEN_PAYLOAD    22
#define AUTHENTICATION_ERROR            120
#define AUTHENTICATION_USER_NOT_EXIST   121
#define AUTHENTICATION_INVALID_ROLE     122
#define AUTHENTICATION_WRONG_PASSWORD   123
#define AUTHENTICATION_NO_LINKED_DEVICE 124

#define VERIFICATION_SUCCESS            30
#define VERIFICATION_SUCCESS_NEW_TOKEN  31
#define VERIFICATION_ERROR              130
#define VERIFICATION_INVALID_TOKEN      131
#define VERIFICATION_INVALID_ROLE       132
#define VERIFICATION_EXPIRED_TOKEN      133

#define INBEHALF_VERIFICATION_SUCCESS            40
#define INBEHALF_VERIFICATION_SUCCESS_NEW_TOKEN  41
#define INBEHALF_VERIFICATION_ERROR              140
#define INBEHALF_VERIFICATION_INVALID_TOKEN      141
#define INBEHALF_VERIFICATION_INVALID_ROLE       142
#define INBEHALF_VERIFICATION_EXPIRED_TOKEN      143

// Define the default messages for each response status code
#define GENERIC_SUCCESS_MSG                 "Success"
#define GENERIC_ERROR_MSG                   "Error"

#define REGISTRATION_SUCCESS_MSG            "Registration success"
#define REGISTRATION_ERROR_MSG              "Registration error"
#define REGISTRATION_USERNAME_IN_USE_MSG    "Registration error: Username already in use"
#define REGISTRATION_EMAIL_IN_USE_MSG       "Registration error: Email already in use"

#define AUTHENTICATION_SUCCESS_MSG          "Authentication success"
#define AUTHENTICATION_TOKEN_COOKIE_MSG     "Authentication success: Token in cookie"
#define AUTHENTICATION_TOKEN_PAYLOAD_MSG    "Authentication success: Token in payload"
#define AUTHENTICATION_ERROR_MSG            "Authentication error"
#define AUTHENTICATION_USER_NOT_EXIST_MSG   "Authentication error: User doesn't exist"
#define AUTHENTICATION_INVALID_ROLE_MSG     "Authentication error: Invalid role claimed"
#define AUTHENTICATION_WRONG_PASSWORD_MSG   "Authentication error: Wrong password"
#define AUTHENTICATION_NO_LINKED_DEVICE_MSG "Authentication error: Account has no linked/forwardable devices"

#define VERIFICATION_SUCCESS_MSG            "Verification success"
#define VERIFICATION_SUCCESS_NEW_TOKEN_MSG  "Verification success with new token"
#define VERIFICATION_ERROR_MSG              "Verification error"
#define VERIFICATION_INVALID_TOKEN_MSG      "Verification error: Invalid token"
#define VERIFICATION_INVALID_ROLE_MSG       "Verification error: Invalid role in token"
#define VERIFICATION_EXPIRED_TOKEN_MSG      "Verification error: Expired token"

#endif  /* AUTHSERVER_RESPONSE_CODES_H */
