#ifndef RINGSERVER_RESPONSE_CODES_H
#define RINGSERVER_RESPONSE_CODES_H

/* Status Code Format: XYZ 
 * X : 0-n based on response group (ie GENERIC is 0, WRITE is 1, AUTHORIZATION is 2, and so on)
 * Y : 0-n increments as type changes within a response group
 * Z : 0 if success type, 1 if error type
 * 
 * For example:
 * 210 :
 * 2 = AUTHENTICATION group
 * 1 = 1st type of response within authentication group  (note: types start at 0 / 0th)
 * 0 = Success code
 */

// Define constant integer values for response status codes
#define GENERIC_SUCCESS                 0
#define GENERIC_ERROR                   1

#define WRITE_SUCCESS                   100
#define WRITE_ERROR                     101
#define WRITE_UNAUTHORIZED              111  // Client has no write permission (token)
#define WRITE_STREAM_UNAUTHORIZED       121  // Client has write permission (token) but doesn't authorize write on this stream
#define WRITE_NO_DEVICE_LINKED          131  // Client has write permission (token) but has no specified device to write on
#define WRITE_EXPIRED_TOKEN             141  // Client's write permission (token) is expired
                                      
// Define response codes as strings
#define GENERIC_SUCCESS_STR                 "GENERIC_SUCCESS"
#define GENERIC_ERROR_STR                   "GENERIC_ERROR"

#define WRITE_SUCCESS_STR                   "WRITE_SUCCESS"
#define WRITE_ERROR_STR                     "WRITE_ERROR"

#define AUTHORIZATION_SUCCESS_STR           "AUTHORIZATION_SUCCESS"
#define AUTHORIZATION_ERROR_STR             "AUTHORIZATION_ERROR"

// Define the default messages for each response status code
#define GENERIC_SUCCESS_MSG                 "Success"
#define GENERIC_ERROR_MSG                   "Error"


#endif  /* RINGSERVER_RESPONSE_CODES_H */
