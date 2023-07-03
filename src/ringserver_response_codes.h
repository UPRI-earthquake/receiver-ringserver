#ifndef RINGSERVER_RESPONSE_CODES_H
#define RINGSERVER_RESPONSE_CODES_H

/* Status Code Format: XYZ
 * X : 0-n based on response group (ie GENERIC is 0, WRITE is 1, AUTH(ORIZATION) is 2, and so on)
 * Y : 0-n increments as type changes within a response group
 * Z : 0 if success type, 1 if error type
 *
 * For example:
 * 210 :
 * 2 = AUTHENTICATION group
 * 1 = 1st type of response within authentication group  (note: types start at 0 / 0th)
 * 0 = Success code
 *
 * Note: Always use the most specific and apt status code for your scenario
 */

// Define constant integer values for response status codes
#define GENERIC_RINGSERVER_SUCCESS        0
#define GENERIC_RINGSERVER_ERROR          1

#define WRITE_SUCCESS                     100  // Catch all success
#define WRITE_ERROR                       101  // Catch all error
#define WRITE_INTERNAL_ERROR              111  // Error due to error in ringserver, when there's nothing slink2dali can do about
#define WRITE_UNAUTHORIZED_ERROR          121  // Client has no write permission (token)
#define WRITE_STREAM_UNAUTHORIZED_ERROR   131  // Client has write permission (token) but doesn't authorize write on this stream
#define WRITE_NO_DEVICE_ERROR             141  // Client has write permission (token) but has no specified device to write on
#define WRITE_EXPIRED_TOKEN_ERROR         151  // Client's write permission (token) is expired
#define WRITE_FORMAT_ERROR                161  // Error in write command formatting leading to parsing error
#define WRITE_LARGE_PACKET_ERROR          171  // Packet is larger than ring packet size

#define AUTH_SUCCESS                      200  // Catch all success
#define AUTH_ERROR                        201  // Catch all error
#define AUTH_INTERNAL_ERROR               211  // Error due to error within ringserver processes
#define AUTH_TOKEN_SIZE_ERROR             221  // Size of token isn't as expected (ie too large)
#define AUTH_INVALID_TOKEN_ERROR          231  // Token is not a valid token from AuthServer
#define AUTH_ROLE_INVALID_ERROR           241  // Role in token isn't what's expected (ie should be sensor)
#define AUTH_EXPIRED_TOKEN_ERROR          251  // Token is expired
#define AUTH_FORMAT_ERROR                 261  // Error in auth command formatting (ie no args given)


// Define response codes as strings
#define GENERIC_RINGSERVER_SUCCESS_STR       "GENERIC_RINGSERVER_SUCCESS"
#define GENERIC_RINGSERVER_ERROR_STR         "GENERIC_RINGSERVER_ERROR"

#define WRITE_SUCCESS_STR                    "WRITE_SUCCESS"
#define WRITE_ERROR_STR                      "WRITE_ERROR"
#define WRITE_INTERNAL_ERROR_STR             "WRITE_INTERNAL_ERROR"
#define WRITE_UNAUTHORIZED_ERROR_STR         "WRITE_UNAUTHORIZED_ERROR"
#define WRITE_STREAM_UNAUTHORIZED_ERROR_STR  "WRITE_STREAM_UNAUTHORIZED_ERROR"
#define WRITE_NO_DEVICE_ERROR_STR            "WRITE_NO_DEVICE_ERROR"
#define WRITE_EXPIRED_TOKEN_ERROR_STR        "WRITE_EXPIRED_TOKEN_ERROR"
#define WRITE_FORMAT_ERROR_STR               "WRITE_FORMAT_ERROR"
#define WRITE_LARGE_PACKET_ERROR_STR         "WRITE_LARGE_PACKET_ERROR"

#define AUTH_SUCCESS_STR                     "AUTH_SUCCESS"
#define AUTH_ERROR_STR                       "AUTH_ERROR"
#define AUTH_INTERNAL_ERROR_STR              "AUTH_INTERNAL_ERROR"
#define AUTH_TOKEN_SIZE_ERROR_STR            "AUTH_TOKEN_SIZE_ERROR"
#define AUTH_INVALID_TOKEN_ERROR_STR         "AUTH_INVALID_TOKEN_ERROR"
#define AUTH_ROLE_INVALID_ERROR_STR          "AUTH_ROLE_INVALID_ERROR"
#define AUTH_EXPIRED_TOKEN_ERROR_STR         "AUTH_EXPIRED_TOKEN_ERROR"
#define AUTH_FORMAT_ERROR_STR                "AUTH_FORMAT_ERROR"

#endif  /* RINGSERVER_RESPONSE_CODES_H */
