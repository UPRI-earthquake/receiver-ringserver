/**************************************************************************
 * dlclient.h
 *
 * Modified: 2016.342
 **************************************************************************/

#ifndef DLCLIENT_H
#define DLCLIENT_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include "rbtree.h"
#include "ringserver.h"

/* DataLink server capability flags */
#define DLCAPFLAGS "DLPROTO:1.0"

#define DLMAXREGEXLEN  1048576  /* Maximum regex pattern size */
#define DL_MAX_NUM_STREAMID  500   /* Maximum number of streamids in JSON payload array of strings.
                                    * Will mostly apply to brgys sending to main server
                                    */
#define DL_MAX_STREAMID_STR_LEN  24   /* Maximum len of streamids string: NET_STAT_.* */

extern int DLHandleCmd (ClientInfo *cinfo);
extern int DLStreamPackets (ClientInfo *cinfo);

#ifdef __cplusplus
}
#endif

#endif /* DLCLIENT_H */
