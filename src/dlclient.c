/**************************************************************************
 * dlclient.c
 *
 * DataLink client thread specific routines.
 *
 * This file is part of the ringserver.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (C) 2020:
 * @author Chad Trabant, IRIS Data Management Center
 **************************************************************************/

 /* _GNU_SOURCE needed to get asprintf() under Linux */
 #define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <curl/curl.h>
#include <libmseed.h>
#include <mxml.h>
#include <pcre.h>
#include <jansson.h>

#include "clients.h"
#include "dlclient.h"
#include "generic.h"
#include "http.h"
#include "logging.h"
#include "mseedscan.h"
#include "rbtree.h"
#include "ring.h"
#include "ringserver.h"
#include "authserver_response_codes.h"
#include "ringserver_response_codes.h"

/* Define the number of no-action loops that trigger the throttle */
#define THROTTLE_TRIGGER 10

static int HandleNegotiation (ClientInfo *cinfo);
static int HandleWrite (ClientInfo *cinfo);
static int HandleRead (ClientInfo *cinfo);
static int HandleInfo (ClientInfo *cinfo, int socket);
static int SendPacket (ClientInfo *cinfo, char *header, char *data,
                       int64_t value, int addvalue, int addsize);
static int SendRingPacket (ClientInfo *cinfo);
static int SelectedStreams (RingParams *ringparams, RingReader *reader);

// helper functions and structs
// Structure to hold the response received from the authentication server
struct MemoryStruct {
  char *memory;
  size_t size;
};
static int requestTokenVerification(char *authserver, char *bearertoken, char *jwt_str, struct MemoryStruct *resp);

/***********************************************************************
 * WriteMemoryCallback:
 *
 * Callback function for CURLOPT_WRITEFUNCTION. Writes received content
 * into user-defined data userp.
 *
 * Returns zero on success, negative value on error.  On success the
 * JSON response is written in resp.
 ***********************************************************************/
size_t WriteMemoryCallback(void *receivedContents, size_t size, size_t nmemb, void *userp) {
  struct MemoryStruct *userStorage = (struct MemoryStruct *)userp; // recast to correct type
  size_t realsize = size * nmemb;

  // allocate memory with correct size, +1 for null terminator
  char *ptr = realloc(userStorage->memory, userStorage->size + realsize + 1);
  if (ptr == NULL) {
    /* Out of memory! */
    printf("Not enough memory (realloc returned NULL)\n");
    return 0;
  }

  userStorage->memory = ptr; // assign to allocated memory
  // copy receivedContents to userStorage, starting on its current size (may be zero)
  memcpy(&(userStorage->memory[userStorage->size]), receivedContents, realsize);
  userStorage->size += realsize; // increment size with amount copied
  userStorage->memory[userStorage->size] = '\0'; // add null terminator to be a valid C str

  return realsize; // return number of bytes written
}

/***********************************************************************
 * requestTokenVerification:
 *
 * Sends an HTTPS POST request to the authserver with the jwt_str as a
 * payload to be verified, and bearertoken is for accessing the
 * authserver endpoint (our own authorization token).
 *
 * Returns zero on success, negative value on error.  On success the
 * JSON response is written in resp.memory as a string.
 ***********************************************************************/

int requestTokenVerification(char *authserver, char *bearertoken,
                             char *jwt_str, struct MemoryStruct *resp) {
  CURL *curl;
  CURLcode res;
  int ret = -1;

  /* Initialize libcurl */
  res = curl_global_init(CURL_GLOBAL_DEFAULT);

  /* get a curl handle */
  curl = curl_easy_init(); // single request

  if (curl) {
    // Set the target URL
    curl_easy_setopt(curl, CURLOPT_URL, authserver);

    // Set the request headers
    struct curl_slist *headers = NULL;

    size_t authHeaderSize = sizeof("Authorization: Bearer ") + strlen(bearertoken) + 1;
    char* authHeader = (char*)malloc(authHeaderSize);
    snprintf(authHeader, authHeaderSize, "Authorization: Bearer %s", bearertoken);

    headers = curl_slist_append(headers, authHeader);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Set the callback function to parse the response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)resp);

    // Set the request payload
    size_t jsonPayloadSize = strlen(jwt_str) + 14; // 13 additional characters for the JSON structure
                                                   // plus 1 for null termination
    char *jsonPayload = malloc(jsonPayloadSize);
    if (jsonPayload == NULL) {
      lprintf(0, "Error allocating memory for JSON payload\n");
    }
    snprintf(jsonPayload, jsonPayloadSize, "{\"token\": \"%s\"}", jwt_str);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload);

    // Perform the POST request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      lprintf(0, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
      ret = 0;
    }

    // Clean up
    free(authHeader);
    free(jsonPayload);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }

  curl_global_cleanup();

  return ret;
}



/***********************************************************************
 * DLHandleCmd:
 *
 * Handle DataLink command, which is expected to be in the
 * ClientInfo.recvbuf buffer.
 *
 * Returns zero on success, negative value on error.  On error the
 * client should be disconnected.
 ***********************************************************************/
int
DLHandleCmd (ClientInfo *cinfo)
{
  if (!cinfo)
    return -1;

  /* Determine if this is a data submission and handle */
  if (!strncmp (cinfo->recvbuf, "WRITE", 5))
  {
    /* Check for write permission */
    /* NOTE: if client has writeperm (see conf WriteIP), then that overrides token requirement,
     * meaning they may send even without AUTHORIZATION command
     */
    if (!cinfo->authorized)
    {
      char replystr[200];

      lprintf (1, "[%s] %s: Data packet received from client without write permission",
          cinfo->hostname, WRITE_UNAUTHORIZED_ERROR_STR);
      snprintf (replystr, sizeof (replystr), "%s(%d): Write request not granted, no token provided",
          WRITE_UNAUTHORIZED_ERROR_STR, WRITE_UNAUTHORIZED_ERROR);
      SendPacket (cinfo, "ERROR",replystr, 0, 1, 1);

      return -1;
    }
    /* Any errors from HandleWrite are fatal */
    else if (HandleWrite (cinfo))
    {
      return -1;
    }
  }

  /* Determine if this is an INFO request and handle */
  else if (!strncmp (cinfo->recvbuf, "INFO", 4))
  {
    /* Any errors from HandleInfo are fatal */
    if (HandleInfo (cinfo, cinfo->socket))
    {
      return -1;
    }
  }

  /* Determine if this is a specific read request and handle */
  else if (!strncmp (cinfo->recvbuf, "READ", 4))
  {
    cinfo->state = STATE_COMMAND;

    /* Any errors from HandleRead are fatal */
    if (HandleRead (cinfo))
    {
      return -1;
    }
  }

  /* Determine if this is a request to start STREAMing and set state */
  else if (!strncmp (cinfo->recvbuf, "STREAM", 6))
  {
    /* Set read position to next packet if position not set */
    if (cinfo->reader->pktid == 0)
    {
      cinfo->reader->pktid = RINGNEXT;
    }

    cinfo->state = STATE_STREAM;
  }

  /* Determine if this is a request to end STREAMing and set state */
  else if (!strncmp (cinfo->recvbuf, "ENDSTREAM", 9))
  {
    /* Send ENDSTREAM */
    if (SendPacket (cinfo, "ENDSTREAM", NULL, 0, 0, 0))
    {
      return -1;
    }

    cinfo->state = STATE_COMMAND;
  }

  /* Otherwise a negotiation command */
  else
  {
    /* If this is not an ID request, set to a non-streaming state */
    if (strncmp (cinfo->recvbuf, "ID", 2))
      cinfo->state = STATE_COMMAND;

    /* Any errors from HandleNegotiation are fatal */
    if (HandleNegotiation (cinfo))
    {
      return -1;
    }
  }

  return 0;
} /* End of DLHandleCmd() */

/***********************************************************************
 * DLStreamPackets:
 *
 * Send selected ring packets to DataLink client.
 *
 * Returns packet size sent on success, zero when no packet sent,
 * negative value on error.  On error the client should disconnected.
 ***********************************************************************/
int
DLStreamPackets (ClientInfo *cinfo)
{
  int64_t readid;

  if (!cinfo)
    return -1;

  /* Read next packet from ring */
  readid = RingReadNext (cinfo->reader, &cinfo->packet, cinfo->packetdata);

  if (readid < 0)
  {
    lprintf (0, "[%s] Error reading next packet from ring", cinfo->hostname);
    return -1;
  }
  else if (readid > 0)
  {
    lprintf (3, "[%s] Read %s (%u bytes) packet ID %" PRId64 " from ring",
             cinfo->hostname, cinfo->packet.streamid,
             cinfo->packet.datasize, cinfo->packet.pktid);

    /* Send packet to client */
    if (SendRingPacket (cinfo))
    {
      if (cinfo->socketerr != 2)
        lprintf (1, "[%s] Error sending packet to client", cinfo->hostname);

      return -1;
    }

    /* Socket errors are fatal */
    if (cinfo->socketerr)
      return -1;
  }
  /* Otherwise there was no next packet */
  else
  {
    return 0;
  }

  return (readid) ? cinfo->packet.datasize : 0;
} /* End of DLStreamPackets() */

/***************************************************************************
 * HandleNegotiation:
 *
 * Handle negotiation commands implementing server-side DataLink
 * protocol, updating the connection configuration accordingly.
 *
 * DataLink commands handled:
 * ID
 * POSITION SET pktid [pkttime]
 * POSITION AFTER datatime
 * MATCH size|<match pattern of length size>
 * REJECT size|<match pattern of length size>
 *
 * All commands handled by this function will return the resulting
 * status to the client.
 *
 * Returns 0 on success and -1 on error which should disconnect.
 ***************************************************************************/
static int
HandleNegotiation (ClientInfo *cinfo)
{
  char sendbuffer[300];
  int size;
  int fields;
  int selected;

  char OKGO = 1;
  char junk;

  /* ID - Return server ID, version and capability flags */
  if (!strncasecmp (cinfo->recvbuf, "ID", 2))
  {
    /* Parse client ID from command if included
     * Everything after "ID " is the client ID */
    if (strlen (cinfo->recvbuf) > 3)
    {
      strncpy (cinfo->clientid, cinfo->recvbuf + 3, sizeof (cinfo->clientid) - 1);
      *(cinfo->clientid + sizeof(cinfo->clientid) - 1) = '\0';
      lprintf (2, "[%s] Received ID (%s)", cinfo->hostname, cinfo->clientid);
    }
    else
    {
      lprintf (2, "[%s] Received ID", cinfo->hostname);
    }

    /* Create server version and capability flags string (DLCAPSFLAGS + WRITE if permission) */
    snprintf (sendbuffer, sizeof (sendbuffer),
              "ID DataLink " VERSION " :: %s PACKETSIZE:%lu%s", DLCAPFLAGS,
              (unsigned long int)(cinfo->ringparams->pktsize - sizeof (RingPacket)),
              (cinfo->writeperm) ? " WRITE" : "");

    /* Send the server ID string */
    if (SendPacket (cinfo, sendbuffer, NULL, 0, 0, 0))
      return -1;
  }

  /* POSITION <SET|AFTER> value [time]\r\n - Set ring reading position */
  else if (!strncasecmp (cinfo->recvbuf, "POSITION", 8))
  {
    char subcmd[10];
    char value[30];
    char subvalue[30];
    int64_t pktid = 0;
    hptime_t hptime;

    OKGO = 1;

    /* Parse sub-command and value from request */
    fields = sscanf (cinfo->recvbuf, "%*s %10s %30s %30s %c",
                     subcmd, value, subvalue, &junk);

    /* Make sure the subcommand, value and subvalue fields are terminated */
    subcmd[9] = '\0';
    value[29] = '\0';
    subvalue[29] = '\0';

    /* Make sure we got a single pattern or no pattern */
    if (fields < 2 || fields > 3)
    {
      if (SendPacket (cinfo, "ERROR", "POSITION requires 2 or 3 arguments", 0, 1, 1))
        return -1;

      OKGO = 0;
    }
    else
    {
      /* Process SET positioning */
      if (!strncmp (subcmd, "SET", 3))
      {
        /* Process SET <pktid> [time] */
        if (IsAllDigits (value))
        {
          pktid = strtoll (value, NULL, 10);
          hptime = (fields == 3) ? strtoll (subvalue, NULL, 10) : HPTERROR;
        }
        /* Process SET EARLIEST */
        else if (!strncmp (value, "EARLIEST", 8))
        {
          pktid = RINGEARLIEST;
          hptime = HPTERROR;
        }
        /* Process SET LATEST */
        else if (!strncmp (value, "LATEST", 6))
        {
          pktid = RINGLATEST;
          hptime = HPTERROR;
        }
        else
        {
          lprintf (0, "[%s] Error with POSITION SET value: %s",
                   cinfo->hostname, value);
          if (SendPacket (cinfo, "ERROR", "Error with POSITION SET value", 0, 1, 1))
            return -1;
          OKGO = 0;
        }

        /* If no errors with the set value do the positioning */
        if (OKGO)
        {
          if ((pktid = RingPosition (cinfo->reader, pktid, hptime)) <= 0)
          {
            if (pktid == 0)
            {
              if (SendPacket (cinfo, "ERROR", "Packet not found", 0, 1, 1))
                return -1;
            }
            else
            {
              lprintf (0, "[%s] Error with RingPosition (pktid: %" PRId64 ", hptime: %" PRId64 ")",
                       cinfo->hostname, pktid, hptime);
              if (SendPacket (cinfo, "ERROR", "Error positioning reader", 0, 1, 1))
                return -1;
            }
          }
          else
          {
            snprintf (sendbuffer, sizeof (sendbuffer),
                      "Positioned to packet ID %" PRId64, pktid);
            if (SendPacket (cinfo, "OK", sendbuffer, pktid, 1, 1))
              return -1;
          }
        }
      }
      /* Process AFTER <time> positioning */
      else if (!strncmp (subcmd, "AFTER", 5))
      {
        if ((hptime = strtoll (value, NULL, 10)) == 0 && errno == EINVAL)
        {
          lprintf (0, "[%s] Error parsing POSITION AFTER time: %s",
                   cinfo->hostname, value);
          if (SendPacket (cinfo, "ERROR", "Error with POSITION AFTER time", 0, 1, 1))
            return -1;
        }
        else
        {
          /* Position ring according to start time, use reverse search if limited */
          if (cinfo->timewinlimit == 1.0)
          {
            pktid = RingAfter (cinfo->reader, hptime, 1);
          }
          else if (cinfo->timewinlimit < 1.0)
          {
            int64_t pktlimit = (int64_t) (cinfo->timewinlimit * cinfo->ringparams->maxpackets);

            pktid = RingAfterRev (cinfo->reader, hptime, pktlimit, 1);
          }
          else
          {
            lprintf (0, "Time window search limit is invalid: %f", cinfo->timewinlimit);
            SendPacket (cinfo, "ERROR", "time window search limit is invalid", 0, 1, 1);
            return -1;
          }

          if (pktid == 0)
          {
            if (SendPacket (cinfo, "ERROR", "Packet not found", 0, 1, 1))
              return -1;
          }
          else if (pktid < 0)
          {
            lprintf (0, "[%s] Error with RingAfter[Rev] (hptime: %" PRId64 ")",
                     cinfo->hostname, hptime);
            if (SendPacket (cinfo, "ERROR", "Error positioning reader", 0, 1, 1))
              return -1;
          }
        }

        snprintf (sendbuffer, sizeof (sendbuffer), "Positioned to packet ID %" PRId64, pktid);
        if (SendPacket (cinfo, "OK", sendbuffer, pktid, 1, 1))
          return -1;
      }
      else
      {
        lprintf (0, "[%s] Unsupported POSITION subcommand: %s", cinfo->hostname, subcmd);
        if (SendPacket (cinfo, "ERROR", "Unsupported POSITION subcommand", 0, 1, 1))
          return -1;
      }
    }
  } /* End of POSITION */

  /* MATCH size\r\n[pattern] - Provide regex to match streamids */
  else if (!strncasecmp (cinfo->recvbuf, "MATCH", 5))
  {
    OKGO = 1;

    /* Parse size from request */
    fields = sscanf (cinfo->recvbuf, "%*s %d %c", &size, &junk);

    /* Make sure we got a single pattern or no pattern */
    if (fields > 1)
    {
      if (SendPacket (cinfo, "ERROR", "MATCH requires a single argument", 0, 1, 1))
        return -1;

      OKGO = 0;
    }
    /* Remove current match if no pattern supplied */
    else if (fields <= 0)
    {
      if (cinfo->matchstr)
        free (cinfo->matchstr);
      cinfo->matchstr = 0;
      RingMatch (cinfo->reader, 0);

      selected = SelectedStreams (cinfo->ringparams, cinfo->reader);
      snprintf (sendbuffer, sizeof (sendbuffer), "%d streams selected after match",
                selected);
      if (SendPacket (cinfo, "OK", sendbuffer, selected, 1, 1))
        return -1;
    }
    else if (size > DLMAXREGEXLEN)
    {
      lprintf (0, "[%s] match expression too large (%d)", cinfo->hostname, size);

      snprintf (sendbuffer, sizeof (sendbuffer), "match expression too large, must be <= %d",
                DLMAXREGEXLEN);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1))
        return -1;

      OKGO = 0;
    }
    else
    {
      if (cinfo->matchstr)
        free (cinfo->matchstr);

      /* Read regex of size bytes from socket */
      if (!(cinfo->matchstr = (char *)malloc (size + 1)))
      {
        lprintf (0, "[%s] Error allocating memory", cinfo->hostname);
        return -1;
      }

      if (RecvData (cinfo, cinfo->matchstr, size) < 0)
      {
        lprintf (0, "[%s] Error Recv'ing data", cinfo->hostname);
        return -1;
      }

      /* Make sure buffer is a terminated string */
      cinfo->matchstr[size] = '\0';

      /* Compile match expression */
      if (RingMatch (cinfo->reader, cinfo->matchstr))
      {
        lprintf (0, "[%s] Error with match expression", cinfo->hostname);

        if (SendPacket (cinfo, "ERROR", "Error with match expression", 0, 1, 1))
          return -1;
      }
      else
      {
        selected = SelectedStreams (cinfo->ringparams, cinfo->reader);
        snprintf (sendbuffer, sizeof (sendbuffer), "%d streams selected after match",
                  selected);
        if (SendPacket (cinfo, "OK", sendbuffer, selected, 1, 1))
          return -1;
      }
    }
  } /* End of MATCH */

  /* REJECT size\r\n[pattern] - Provide regex to reject streamids */
  else if (OKGO && !strncasecmp (cinfo->recvbuf, "REJECT", 6))
  {
    OKGO = 1;

    /* Parse size from request */
    fields = sscanf (cinfo->recvbuf, "%*s %d %c", &size, &junk);

    /* Make sure we got a single pattern or no pattern */
    if (fields > 1)
    {
      if (SendPacket (cinfo, "ERROR", "REJECT requires a single argument", 0, 1, 1))
        return -1;

      OKGO = 0;
    }
    /* Remove current reject if no pattern supplied */
    else if (fields <= 0)
    {
      if (cinfo->rejectstr)
        free (cinfo->rejectstr);
      cinfo->rejectstr = 0;
      RingReject (cinfo->reader, 0);

      selected = SelectedStreams (cinfo->ringparams, cinfo->reader);
      snprintf (sendbuffer, sizeof (sendbuffer), "%d streams selected after reject",
                selected);
      if (SendPacket (cinfo, "OK", sendbuffer, selected, 1, 1))
        return -1;
    }
    else if (size > DLMAXREGEXLEN)
    {
      lprintf (0, "[%s] reject expression too large (%d)", cinfo->hostname, size);

      snprintf (sendbuffer, sizeof (sendbuffer), "reject expression too large, must be <= %d",
                DLMAXREGEXLEN);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1))
        return -1;

      OKGO = 0;
    }
    else
    {
      if (cinfo->rejectstr)
        free (cinfo->rejectstr);

      /* Read regex of size bytes from socket */
      if (!(cinfo->rejectstr = (char *)malloc (size + 1)))
      {
        lprintf (0, "[%s] Error allocating memory", cinfo->hostname);
        return -1;
      }

      if (RecvData (cinfo, cinfo->rejectstr, size) < 0)
      {
        lprintf (0, "[%s] Error Recv'ing data", cinfo->hostname);
        return -1;
      }

      /* Make sure buffer is a terminated string */
      cinfo->rejectstr[size] = '\0';

      /* Compile reject expression */
      if (RingReject (cinfo->reader, cinfo->rejectstr))
      {
        lprintf (0, "[%s] Error with reject expression", cinfo->hostname);

        if (SendPacket (cinfo, "ERROR", "Error with reject expression", 0, 1, 1))
          return -1;
      }
      else
      {
        selected = SelectedStreams (cinfo->ringparams, cinfo->reader);
        snprintf (sendbuffer, sizeof (sendbuffer), "%d streams selected after reject",
                  selected);
        if (SendPacket (cinfo, "OK", sendbuffer, selected, 1, 1))
          return -1;
      }
    }
  } /* End of REJECT */

  /* AUTHORIZATION size\r\n[token] - token authorization for write */
  else if (!strncasecmp (cinfo->recvbuf, "AUTHORIZATION", 13))
  {
    /* Parse size from request */
    fields = sscanf (cinfo->recvbuf, "%*s %d %c", &size, &junk);

    /* Make sure we got a single pattern or no pattern */
    if (fields > 1)
    {
      lprintf (0, "[%s] %s: AUTHORIZATION requires a single argument", cinfo->hostname, AUTH_FORMAT_ERROR_STR);
      snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): AUTHORIZATION requires a single argument",
                AUTH_FORMAT_ERROR_STR, AUTH_FORMAT_ERROR);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1)){
        return -1;
      } else {
        return 0; // means negotiation completed (we've responded)
      }
    }

    /* Check received token size */
    if (size > DLMAXREGEXLEN)
    {
      lprintf (0, "[%s] %s: Authorization token too large (%d)", cinfo->hostname, AUTH_TOKEN_SIZE_ERROR_STR, size);
      snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): Authorization token too large (%d), must be <= %d",
                AUTH_TOKEN_SIZE_ERROR_STR, AUTH_TOKEN_SIZE_ERROR, size, DLMAXREGEXLEN);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1)) {
        return -1;
      } else {
        return 0;
      }
    }

    /* Check if AuthServer is configured */
    if ( ! authserver)
    {
      lprintf (0, "[%s] %s: Cannot authorize for write, AuthServer-setting not configured", cinfo->hostname, AUTH_INTERNAL_ERROR_STR);

      snprintf (sendbuffer, sizeof (sendbuffer),
          "%s(%d): Cannot authorize for write, RingServer not properly configured",
          AUTH_INTERNAL_ERROR_STR, AUTH_INTERNAL_ERROR);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1)) {
        return -1;
      } else {
        return 0;
      }
    }

    /* Check if BearerToken is configured */
    if (! authdir)
    {
      lprintf (0, "[%s] %s: Cannot authorize for write, BearerToken-setting not configured", cinfo->hostname, AUTH_INTERNAL_ERROR_STR);

      snprintf (sendbuffer, sizeof (sendbuffer),
          "%s(%d): Cannot authorize for write, RingServer not properly configured",
          AUTH_INTERNAL_ERROR_STR, AUTH_INTERNAL_ERROR);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1)) {
        return -1;
      } else {
        return 0;
      }
    }

    /* Get bearertoken from authdir/secret.key */
    char *keypath = NULL;
    char *keyfilename = NULL;
    struct stat filestat;
    FILE *fp;
    int key_len = 0;

    // read key to verify
    if (asprintf (&keypath, "%s/%s", authdir, "secret.key") < 0)
      return -1;

    keyfilename = realpath (keypath, NULL);
    if (keyfilename == NULL)
    {
      lprintf (0, "[%s] Error resolving path to token file: %s", cinfo->hostname, keypath);
      return -1;
    }

    // Get file attributes into filestat (NOTE: not used...)
    if (stat (keyfilename, &filestat))
      return -1;

    // Open file
    if ((fp = fopen (keyfilename, "r")) == NULL)
    {
      lprintf (0, "[%s] Error opening token file %s:  %s",
               cinfo->hostname, keyfilename, strerror (errno));
      return -1;
    }

    // Obtain the size of the file
    fseek(fp, 0, SEEK_END);         // change cursor to 0 offset from end
    long file_size = ftell(fp);     // get current position of file pointer
    fseek(fp, 0, SEEK_SET);         // putback cursor to 0 offset from start
    if (file_size > DLMAXREGEXLEN){
      lprintf (0, "[%s] Token in authdir/secret.key is too large: %ld",
               cinfo->hostname, file_size);
      return -1;
    }

    // Allocate memory
    char *bearertoken = malloc(file_size + 1);
    if (bearertoken == NULL) {
      lprintf(0, "[%s] Failed to allocate memory for bearertoken", cinfo->hostname);
      return -1;
    }

    // Read token from authdir/secret.key into bearertoken
    key_len = fread(bearertoken, 1, file_size, fp);
    if (key_len != file_size) {
      lprintf(0, "[%s] Error reading bearertoken from authdir/secret.key", cinfo->hostname);
      return -1;
    }
    fclose(fp);

    // Terminate properly
    bearertoken[key_len] = '\0';
    if ((key_len > 0) && (bearertoken[key_len-1] == '\n')) {
      bearertoken[key_len-1] = '\0'; //zap newline
    }


    /* Proceed to token verification */


    /* Get client token from dali AUTHORIZATION command */
    char *jwt_str = NULL;
    struct MemoryStruct response;

    if (cinfo->jwttoken){ // Erase any recently stored token for this connection
      jwt_free( cinfo->jwttoken);
    }

    // Allocate memory for jwt holder
    if (!(jwt_str = (char *)malloc (size + 1)))
    {
      lprintf (0, "[%s] Error allocating memory", cinfo->hostname);
      return -1;
    }

    // Read token from AUTHORIZATION command data
    if (RecvData (cinfo, jwt_str, size) < 0)
    {
      lprintf (0, "[%s] Error Recv'ing data", cinfo->hostname);
      free(jwt_str);
      return -1;
    }

    // Make sure buffer is a terminated string
    jwt_str[size] = '\0';

    // Ask AuthServer to verify token
    response.memory = malloc(1); // Return a pointer to at least 1 block, will be resized dynamically
    response.size = 0;

    lprintf (1, "[%s] Requesting verification from %s", cinfo->hostname, authserver);
    if (requestTokenVerification(authserver, bearertoken, jwt_str, &response))
    {
      lprintf (0, "[%s] Error requesting verification from %s", cinfo->hostname, authserver);
      free(response.memory);
      free(jwt_str);
      return -1;
    }
    free(jwt_str); // no more need for this
    free(bearertoken); // no more need for this

    lprintf (1, "[%s] %s responded with: %s\n", cinfo->hostname, authserver, response.memory);

    // Convert str response to object
    json_error_t err;
    json_t *jsonResponse = json_loads(response.memory, 0, &err);
    free(response.memory); // no more need for this

    // Check if parsing was successful
    if (jsonResponse == NULL) {
      lprintf(0, "[%s] JSON parsing error: on line %d: %s\n", cinfo->hostname, err.line, err.text);
      return -1;
    }

    // Get first layer of values (except "message")
    json_t *status = json_object_get(jsonResponse, "status");
    json_t *sensorInfo = json_object_get(jsonResponse, "sensorInfo");
    if(
      status == NULL         || ( !json_is_integer(status)  ) ||
      sensorInfo == NULL     || ( !json_is_object(sensorInfo)  )
    ) {
      lprintf (0, "[%s] %s: Error parsing jsonResponse from AuthServer",
          cinfo->hostname, AUTH_INTERNAL_ERROR_STR);
      json_decref(jsonResponse);
      return -1;
    }

    int authserver_response_code = json_integer_value(status);
    int ret = 0;
    if (authserver_response_code == INBEHALF_VERIFICATION_SUCCESS)
    {
      // Get JSON components
      json_t *username = json_object_get(sensorInfo, "username");
      json_t *role = json_object_get(sensorInfo, "role");
      json_t *exp_ptr = json_object_get(sensorInfo, "tokenExp");
      json_t *streamIdsArray = json_object_get(sensorInfo, "streamIds"); // Array of strings

      // Check expected data types
      if(
        username == NULL       || ( !json_is_string(username)    ) ||
        role == NULL           || ( !json_is_string(role)        ) ||
        exp_ptr == NULL        || ( !json_is_integer(exp_ptr)    ) ||
        streamIdsArray == NULL || ( !json_is_array(streamIdsArray) )
      ) {
        json_decref(jsonResponse); // freeing because of early return

        lprintf (0, "[%s] %s: Error parsing sensorInfo from AuthServer response",
            cinfo->hostname, AUTH_INTERNAL_ERROR_STR);
                                   //
        snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): RingServer encountered an error",
            AUTH_INTERNAL_ERROR_STR, AUTH_INTERNAL_ERROR);
        if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1)){
          return -1;
        }else{
          return 0;
        }
      }

      //Assign username and role to cinfo
      cinfo->username = (char*)malloc( (strlen( json_string_value(username) )+1) );
      cinfo->role = (char*)malloc( (strlen( json_string_value(role) )+1) );
      if (cinfo->username == NULL || cinfo->role == NULL) {
        lprintf (0, "[%s] Error allocating memory for username & role", cinfo->hostname);
        json_decref(jsonResponse);
        return -1;
      }
      strncpy(
        cinfo->username, 
        json_string_value(username),
        strlen( json_string_value(username) ) + 1
      );
      strncpy(
        cinfo->role,
        json_string_value(role),
        strlen( json_string_value(role) ) + 1 
      );
      lprintf(1, "[%s] username = %s, role = %s", cinfo->hostname, cinfo->username, cinfo->role);

      // Assign tokenExpiry to cinfo
      cinfo->tokenExpiry = json_integer_value(exp_ptr);
      lprintf(1, "[%s] Token expiration: %d", cinfo->hostname, cinfo->tokenExpiry);


      // Assign StreamIds str and pcre to cinfo
      // Iterate over the elements in the streamIds array
      size_t index;
      json_t *streamId;
      const char *errptr;
      int erroffset;

      // Allocate size of arrays
      cinfo->writepattern_count = 0;
      size_t num_streams = json_array_size(streamIdsArray);
      if (num_streams > DL_MAX_NUM_STREAMID){
        lprintf(0, "Error number of streamIds (%zu) exceeded maximum: %d",
            num_streams, DL_MAX_NUM_STREAMID);
        json_decref(jsonResponse);
        return -1;
      }

      lprintf(1, "[%s] Number of streamIds %zu", cinfo->hostname, num_streams);
      cinfo->writepatterns_str = (char**)malloc(num_streams * sizeof(char*));
      cinfo->writepatterns = (pcre**)malloc(num_streams * sizeof(pcre*));
      if (cinfo->writepatterns == NULL || cinfo->writepatterns_str == NULL) {
        // TODO: Properly handle the error if reallocation fails
        lprintf (0, "[%s] Error allocating memory", cinfo->hostname);

        json_decref(jsonResponse);
        return -1;
      }

      json_array_foreach(streamIdsArray, index, streamId) {
        if (json_is_string(streamId))
        {
          // Compile pcre pattern from string, assign to cinfo
          const char *streamIdStr = json_string_value(streamId);
          pcre *pattern = pcre_compile (streamIdStr, 0, &errptr, &erroffset, NULL); // allocates automatically
          if (errptr){
            lprintf (0, "[%s] %s: Error with JWTToken & pcre_compile: %s (offset: %d)", cinfo->hostname,
                AUTH_INTERNAL_ERROR_STR, errptr, erroffset);
            snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): Internal error occured on RingServer",
                AUTH_INTERNAL_ERROR_STR, AUTH_INTERNAL_ERROR);

            if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1))
              ret = -1;

            json_decref(jsonResponse);
            return ret;
          }
          cinfo->writepatterns[cinfo->writepattern_count] = pattern;

          // assign streamid_str to cinfo
          size_t pattern_str_size = (strlen(streamIdStr)+1) * sizeof(char);
          if (pattern_str_size > DL_MAX_STREAMID_STR_LEN){
            lprintf(0, "Length of streamId string (%s, %lu) exceeded maximum: %d",
                streamIdStr, pattern_str_size, DL_MAX_STREAMID_STR_LEN);
            json_decref(exp_ptr);
            json_decref(sensorInfo);
            json_decref(jsonResponse);
            return -1;
          }
          cinfo->writepatterns_str[cinfo->writepattern_count] = malloc(pattern_str_size);
          strncpy(cinfo->writepatterns_str[cinfo->writepattern_count], streamIdStr, pattern_str_size);

          cinfo->writepattern_count++;
        }
        else
        {
          lprintf(0, "Invalid streamId at index %zu\n", index);

          json_decref(jsonResponse);
          return -1;
        }
      }

      // Print stream IDs
      int i;
      lprintf(1, "[%s] Stream IDs:", cinfo->hostname);
      for (i = 0; i < cinfo->writepattern_count; i++) {
        lprintf(1, "[%s]    %s", cinfo->hostname, cinfo->writepatterns_str[i]);
      }

      // Update write authority flag
      cinfo->authorized = 1;

      // Respond
      lprintf (1, "[%s] %s: Granted authorization to WRITE on streamIds", cinfo->hostname, AUTH_SUCCESS_STR);
      snprintf (sendbuffer, sizeof (sendbuffer),
          "%s(%d): Granted authorization to WRITE on streamIds",
          AUTH_SUCCESS_STR, AUTH_SUCCESS);
      if (SendPacket (cinfo, "OK", sendbuffer, 0, 1, 1))
        ret = -1;
    }
    else if (authserver_response_code == INBEHALF_VERIFICATION_INVALID_TOKEN)
    {
      lprintf (0, "[%s] %s: Sensor token invalid", cinfo->hostname, AUTH_INVALID_TOKEN_ERROR_STR);
      snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): Sensor token invalid",
          AUTH_INVALID_TOKEN_ERROR_STR, AUTH_INVALID_TOKEN_ERROR);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1))
        ret = -1;
    }
    else if (authserver_response_code == INBEHALF_VERIFICATION_INVALID_ROLE)
    {
      lprintf (0, "[%s] %s: Role in token invalid", cinfo->hostname, AUTH_ROLE_INVALID_ERROR_STR);
      snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): Role in token invalid",
          AUTH_ROLE_INVALID_ERROR_STR, AUTH_ROLE_INVALID_ERROR);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1))
        ret = -1;
    }
    else if (authserver_response_code == INBEHALF_VERIFICATION_EXPIRED_TOKEN)
    {
      lprintf (0, "[%s] %s: Expired sensor token", cinfo->hostname, AUTH_EXPIRED_TOKEN_ERROR_STR);
      snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): Expired sensor token",
          AUTH_EXPIRED_TOKEN_ERROR_STR, AUTH_EXPIRED_TOKEN_ERROR);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1))
        ret = -1;
    }
    else
    {
      // TODO: Specifically handle other cases such as the VERIFICATION cases for bearertoken
      lprintf (0, "[%s] %s: Error code from AuthServer = %d", cinfo->hostname, AUTH_INTERNAL_ERROR_STR,
          authserver_response_code);
      snprintf (sendbuffer, sizeof (sendbuffer), "%s(%d): Internal error occured on RingServer",
          AUTH_INTERNAL_ERROR_STR, AUTH_INTERNAL_ERROR);
      if (SendPacket (cinfo, "ERROR", sendbuffer, 0, 1, 1))
        ret = -1;
    }

    // Cleanup
    json_decref(jsonResponse);
    return ret;
  }

  /* BYE - End connection */
  else if (!strncasecmp (cinfo->recvbuf, "BYE", 3))
  {
    return -1;
  }

  /* Unrecognized command */
  else
  {
    lprintf (1, "[%s] Unrecognized command: %.10s",
             cinfo->hostname, cinfo->recvbuf);

    if (SendPacket (cinfo, "ERROR", "Unrecognized command", 0, 1, 1))
      return -1;
  }

  return 0;
} /* End of HandleNegotiation */

/***************************************************************************
 * HandleWrite:
 *
 * Handle DataLink WRITE request.
 *
 * The command syntax is: "WRITE <streamid> <hpdatastart> <hpdataend> <flags> <datasize>"
 *
 * The stream ID is used verbatim by the ringserver.  The hpdatastart
 * and hpdataend are high-precision time stamps (dltime_t).  The data
 * size is the size in bytes of the data portion following the header.
 * The flags are single character indicators and interpreted the
 * following way:
 *
 * flags:
 * 'N' = no acknowledgement is requested
 * 'A' = acknowledgement is requested, server will send a reply
 *
 * Returns 0 on success and -1 on error which should disconnect.
 ***************************************************************************/
static int
HandleWrite (ClientInfo *cinfo)
{
  StreamNode *stream;
  char replystr[200];
  char streamid[100];
  char flags[100];
  int nread;
  int newstream = 0;
  int rv;

  MSRecord *msr = 0;
  char *type;
  pcre_extra *match_extra = NULL;
  int pcre_result = 0;
  uint8_t found_match = 0;
  uint8_t drop_packet = 0;

  if (!cinfo)
    return -1;

  /* Parse command parameters: WRITE <streamid> <datastart> <dataend> <flags> <datasize> */
  if (sscanf (cinfo->recvbuf, "%*s %100s %" PRId64 " %" PRId64 " %100s %u",
              streamid, &(cinfo->packet.datastart), &(cinfo->packet.dataend),
              flags, &(cinfo->packet.datasize)) != 5)
  {
    lprintf (1, "[%s] %s: Error parsing WRITE parameters: %.100s",
             cinfo->hostname, WRITE_FORMAT_ERROR_STR, cinfo->recvbuf);
    snprintf (replystr, sizeof (replystr), "%s(%d): Error parsing your WRITE command parameters",
        WRITE_FORMAT_ERROR_STR, WRITE_FORMAT_ERROR);
    SendPacket (cinfo, "ERROR", replystr, 0, 1, 1);

    return -1;
  }

  /* Check authority to WRITE on patterns*/
  if (!cinfo->writepatterns)
  {
    lprintf (1, "[%s] %s: Client has no linked devices, %s is not linked",
             cinfo->hostname, WRITE_NO_DEVICE_ERROR_STR, streamid);
    snprintf (replystr, sizeof (replystr), "%s(%d): You have no linked devices, %s is not linked",
        WRITE_NO_DEVICE_ERROR_STR, WRITE_NO_DEVICE_ERROR, streamid);
    SendPacket (cinfo, "ERROR", replystr, 0, 1, 1);

    return -1;
  }

  /* Check if token is expired */
  time_t currTime = time(NULL);
  if (currTime > cinfo->tokenExpiry) {
    lprintf (1, "[%s] %s: Client token expired: %lu > %d",
             cinfo->hostname, WRITE_EXPIRED_TOKEN_ERROR_STR, currTime, cinfo->tokenExpiry);
    snprintf (replystr, sizeof (replystr), "%s(%d): Your token has expired",
        WRITE_EXPIRED_TOKEN_ERROR_STR, WRITE_EXPIRED_TOKEN_ERROR);
    SendPacket (cinfo, "ERROR", replystr, 0, 1, 1);
    return -1;
  }

  /* Check if streamid of packet to be written is in array of allowed client's writepatterns*/
  found_match = 0;
  for(int i = 0; i < cinfo->writepattern_count; i++){ // TODO: Optimize this? (see DL_MAX_NUM_STREAMID)
    pcre_result = pcre_exec (cinfo->writepatterns[i], match_extra, streamid, strlen (streamid), 0, 0, NULL, 0);
    if (match_extra) {
      pcre_free(match_extra);  // deallocate the memory
      match_extra = NULL;      // make pointer point to nothing for next iteration
    }

    if(pcre_result<0){ // PCRE_ERROR_NOMATCH=-1
      continue;
    }else{
      found_match = 1;
      break;
    }
  }

  if(found_match)
  {
      lprintf (3, "[%s]: Token authorized to WRITE on streamid: %s, pcre_result: %d",
               cinfo->hostname, streamid, pcre_result);
  }
  else
  {
      drop_packet = 1;  // We'll receive the data-packet but won't write it and we won't disconnect
  }

  /* Copy the stream ID */
  memcpy (cinfo->packet.streamid, streamid, sizeof (cinfo->packet.streamid));

  /* Make sure the streamid is terminated */
  cinfo->packet.streamid[sizeof (cinfo->packet.streamid) - 1] = '\0';

  /* Make sure this packet data would fit into the ring */
  if (cinfo->packet.datasize > cinfo->ringparams->pktsize)
  {
    lprintf (1, "[%s] %s: Submitted packet size (%d) is greater than ring packet size (%d)",
             cinfo->hostname, WRITE_LARGE_PACKET_ERROR_STR,
             cinfo->packet.datasize, cinfo->ringparams->pktsize);

    snprintf (replystr, sizeof (replystr), "%s(%d): Packet size (%d) is too large for ring, maximum is %d bytes",
              WRITE_LARGE_PACKET_ERROR_STR, WRITE_LARGE_PACKET_ERROR,
              cinfo->packet.datasize, cinfo->ringparams->pktsize);
    SendPacket (cinfo, "ERROR", replystr, 0, 1, 1);

    return -1;
  }

  /* Recv packet data from socket */
  nread = RecvData (cinfo, cinfo->packetdata, cinfo->packet.datasize);

  if (nread < 0)
    return -1;

  /* Drop packet if unauthorized to write on this stream */ 
  if (drop_packet)
  {
      lprintf (1, "[%s] %s: Dropping packet. Client not authorized to WRITE on streamid: %s",
               cinfo->hostname, WRITE_STREAM_UNAUTHORIZED_ERROR_STR, streamid);
      snprintf (replystr, sizeof (replystr), "%s(%d): Dropping packet. You are not authorized to WRITE on %s",
          WRITE_STREAM_UNAUTHORIZED_ERROR_STR, WRITE_STREAM_UNAUTHORIZED_ERROR, streamid);
      if (SendPacket (cinfo, "ERROR", replystr, 0, 1, 1))
        return -1;

      return 0; // don't disconnect
  }

  /* Write received miniSEED to a disk archive if configured */
  if (cinfo->mswrite)
  {
    char filename[100];
    char *fn;

    if ((type = strrchr (streamid, '/')))
    {
      if (!strncmp (++type, "MSEED", 5))
      {
        /* Parse the miniSEED record header */
        if (msr_unpack (cinfo->packetdata, cinfo->packet.datasize, &msr, 0, 0) == MS_NOERROR)
        {
          /* Check for file name in streamid: "filename::streamid/MSEED" */
          if ((fn = strstr (streamid, "::")))
          {
            strncpy (filename, streamid, (fn - streamid));
            filename[(fn - streamid)] = '\0';
            fn = filename;
          }

          /* Write miniSEED record to disk */
          if (ds_streamproc (cinfo->mswrite, msr, fn, cinfo->hostname))
          {
            lprintf (1, "[%s] Error writing miniSEED to disk", cinfo->hostname);
            snprintf (replystr, sizeof (replystr), "%s(%d): Error writing miniSEED to disk",
                      WRITE_INTERNAL_ERROR_STR, WRITE_INTERNAL_ERROR);
            SendPacket (cinfo, "ERROR", replystr, 0, 1, 1);

            return -1;
          }
        }

        if (msr)
          msr_free (&msr);
      }
    }
  }

  /* Add the packet to the ring */
  if ((rv = RingWrite (cinfo->ringparams, &cinfo->packet, cinfo->packetdata, cinfo->packet.datasize)))
  {
    if (rv == -2)
      lprintf (1, "[%s] Error with RingWrite, corrupt ring, shutdown signalled", cinfo->hostname);
    else
      lprintf (1, "[%s] %s: Error with RingWrite", cinfo->hostname, WRITE_INTERNAL_ERROR_STR);

    snprintf (replystr, sizeof (replystr), "%s(%d): Error adding packet to ring",
              WRITE_INTERNAL_ERROR_STR, WRITE_INTERNAL_ERROR);
    SendPacket (cinfo, "ERROR", replystr, 0, 1, 1);

    /* Set the shutdown signal if ring corruption was detected */
    if (rv == -2)
      shutdownsig = 1;

    return -1;
  }

  /* Get (creating if needed) the StreamNode for this streamid */
  if ((stream = GetStreamNode (cinfo->streams, &cinfo->streams_lock,
                               cinfo->packet.streamid, &newstream)) == 0)
  {
    lprintf (0, "[%s] Error with GetStreamNode for %s",
             cinfo->hostname, cinfo->packet.streamid);
    return -1;
  }

  if (newstream)
  {
    lprintf (3, "[%s] New stream for client: %s", cinfo->hostname, cinfo->packet.streamid);
    cinfo->streamscount++;
  }

  /* Update StreamNode packet and byte counts */
  pthread_mutex_lock (&(cinfo->streams_lock));
  stream->rxpackets++;
  stream->rxbytes += cinfo->packet.datasize;
  pthread_mutex_unlock (&(cinfo->streams_lock));

  /* Update client receive counts */
  cinfo->rxpackets[0]++;
  cinfo->rxbytes[0] += cinfo->packet.datasize;

  /* Send acknowledgement if requested (flags contain 'A') */
  if (strchr (flags, 'A'))
  {
    snprintf (replystr, sizeof (replystr), "%s(%d): Packet written in RingServer",
              WRITE_SUCCESS_STR, WRITE_SUCCESS);
    if (SendPacket (cinfo, "OK", replystr, cinfo->packet.pktid, 1, 1))
      return -1;
  }

  return (cinfo->socketerr) ? -1 : 0;
} /* End of HandleWrite */

/***************************************************************************
 * HandleRead:
 *
 * Handle DataLink READ request.
 *
 * The command syntax is: "READ <pktid>"
 *
 * Returns 0 on success and -1 on error which should disconnect.
 ***************************************************************************/
static int
HandleRead (ClientInfo *cinfo)
{
  int64_t reqid = 0;
  int64_t readid = 0;
  char replystr[100];

  if (!cinfo)
    return -1;

  /* Parse command parameters: READ <pktid> */
  if (sscanf (cinfo->recvbuf, "%*s %" PRId64, &reqid) != 1)
  {
    lprintf (1, "[%s] Error parsing READ parameters: %.100s",
             cinfo->hostname, cinfo->recvbuf);

    if (SendPacket (cinfo, "ERROR", "Error parsing READ command parameters", 0, 1, 1))
      return -1;
  }

  /* Read the packet from the ring */
  if ((readid = RingRead (cinfo->reader, reqid, &cinfo->packet, cinfo->packetdata)) < 0)
  {
    lprintf (1, "[%s] Error with RingRead", cinfo->hostname);

    if (SendPacket (cinfo, "ERROR", "Error reading packet from ring", 0, 1, 1))
      return -1;
  }

  /* Return packet not found error message if needed */
  if (readid == 0)
  {
    snprintf (replystr, sizeof (replystr), "Packet %" PRId64 " not found in ring", reqid);
    if (SendPacket (cinfo, "ERROR", replystr, 0, 1, 1))
      return -1;
  }
  /* Send packet to client */
  else if (SendRingPacket (cinfo))
  {
    if (cinfo->socketerr != 2)
      lprintf (1, "[%s] Error sending packet to client", cinfo->hostname);
  }

  return (cinfo->socketerr) ? -1 : 0;
} /* End of HandleRead() */

/***************************************************************************
 * HandleInfo:
 *
 * Handle DataLink INFO request, returning the appropriate XML response.
 *
 * DataLink INFO requests handled:
 * STATUS
 * STREAMS
 * CONNECTIONS
 *
 * Returns 0 on success and -1 on error which should disconnect.
 ***************************************************************************/
static int
HandleInfo (ClientInfo *cinfo, int socket)
{
  mxml_node_t *xmldoc = 0;
  mxml_node_t *status;
  char string[200];
  char *xmlstr = 0;
  int xmllength;
  char *type = 0;
  char *matchexpr = 0;
  char errflag = 0;

  if (!cinfo)
    return -1;

  if (!strncasecmp (cinfo->recvbuf, "INFO", 4))
  {
    /* Set level pointer to start of type identifier */
    type = cinfo->recvbuf + 4;

    /* Skip any spaces between INFO and type identifier */
    while (*type == ' ')
      type++;

    /* Skip type characters then spaces to get to match */
    matchexpr = type;
    while (*matchexpr != ' ' && *matchexpr)
      matchexpr++;
    while (*matchexpr == ' ')
      matchexpr++;
  }
  else
  {
    lprintf (0, "[%s] HandleInfo cannot detect INFO", cinfo->hostname);
    return -1;
  }

  /* Initialize the XML response */
  if (!(xmldoc = mxmlNewElement (MXML_NO_PARENT, "DataLink")))
  {
    lprintf (0, "[%s] Error initializing XML response", cinfo->hostname);
    return -1;
  }

  /* All INFO responses contain these attributes in the root DataLink element */
  mxmlElementSetAttr (xmldoc, "Version", VERSION);
  mxmlElementSetAttr (xmldoc, "ServerID", serverid);
  mxmlElementSetAttrf (xmldoc, "Capabilities", "%s PACKETSIZE:%lu%s", DLCAPFLAGS,
                       (unsigned long int)(cinfo->ringparams->pktsize - sizeof (RingPacket)),
                       (cinfo->writeperm) ? " WRITE" : "");

  /* All INFO responses contain the "Status" element */
  if (!(status = mxmlNewElement (xmldoc, "Status")))
  {
    lprintf (0, "[%s] Error adding child to XML INFO response", cinfo->hostname);
    errflag = 1;
  }
  else
  {
    /* Convert server start time to YYYY-MM-DD HH:MM:SS */
    ms_hptime2mdtimestr (serverstarttime, string, 0);
    mxmlElementSetAttr (status, "StartTime", string);
    mxmlElementSetAttrf (status, "RingVersion", "%u", (unsigned int)cinfo->ringparams->version);
    mxmlElementSetAttrf (status, "RingSize", "%" PRIu64, cinfo->ringparams->ringsize);
    mxmlElementSetAttrf (status, "PacketSize", "%lu",
                         (unsigned long int)(cinfo->ringparams->pktsize - sizeof (RingPacket)));
    mxmlElementSetAttrf (status, "MaximumPacketID", "%" PRId64, cinfo->ringparams->maxpktid);
    mxmlElementSetAttrf (status, "MaximumPackets", "%" PRId64, cinfo->ringparams->maxpackets);
    mxmlElementSetAttrf (status, "MemoryMappedRing", "%s", (cinfo->ringparams->mmapflag) ? "TRUE" : "FALSE");
    mxmlElementSetAttrf (status, "VolatileRing", "%s", (cinfo->ringparams->volatileflag) ? "TRUE" : "FALSE");
    mxmlElementSetAttrf (status, "TotalConnections", "%d", clientcount);
    mxmlElementSetAttrf (status, "TotalStreams", "%d", cinfo->ringparams->streamcount);
    mxmlElementSetAttrf (status, "TXPacketRate", "%.1f", cinfo->ringparams->txpacketrate);
    mxmlElementSetAttrf (status, "TXByteRate", "%.1f", cinfo->ringparams->txbyterate);
    mxmlElementSetAttrf (status, "RXPacketRate", "%.1f", cinfo->ringparams->rxpacketrate);
    mxmlElementSetAttrf (status, "RXByteRate", "%.1f", cinfo->ringparams->rxbyterate);
    mxmlElementSetAttrf (status, "EarliestPacketID", "%" PRId64, cinfo->ringparams->earliestid);
    ms_hptime2mdtimestr (cinfo->ringparams->earliestptime, string, 1);
    mxmlElementSetAttr (status, "EarliestPacketCreationTime",
                        (cinfo->ringparams->earliestptime != HPTERROR) ? string : "-");
    ms_hptime2mdtimestr (cinfo->ringparams->earliestdstime, string, 1);
    mxmlElementSetAttr (status, "EarliestPacketDataStartTime",
                        (cinfo->ringparams->earliestdstime != HPTERROR) ? string : "-");
    ms_hptime2mdtimestr (cinfo->ringparams->earliestdetime, string, 1);
    mxmlElementSetAttr (status, "EarliestPacketDataEndTime",
                        (cinfo->ringparams->earliestdetime != HPTERROR) ? string : "-");
    mxmlElementSetAttrf (status, "LatestPacketID", "%" PRId64, cinfo->ringparams->latestid);
    ms_hptime2mdtimestr (cinfo->ringparams->latestptime, string, 1);
    mxmlElementSetAttr (status, "LatestPacketCreationTime",
                        (cinfo->ringparams->latestptime != HPTERROR) ? string : "-");
    ms_hptime2mdtimestr (cinfo->ringparams->latestdstime, string, 1);
    mxmlElementSetAttr (status, "LatestPacketDataStartTime",
                        (cinfo->ringparams->latestdstime != HPTERROR) ? string : "-");
    ms_hptime2mdtimestr (cinfo->ringparams->latestdetime, string, 1);
    mxmlElementSetAttr (status, "LatestPacketDataEndTime",
                        (cinfo->ringparams->latestdetime != HPTERROR) ? string : "-");
  }

  /* Add contents to the XML structure depending on info request */
  if (!strncasecmp (type, "STATUS", 6))
  {
    mxml_node_t *stlist, *st;
    int totalcount = 0;
    struct sthread *loopstp;

    lprintf (1, "[%s] Received INFO STATUS request", cinfo->hostname);
    type = "INFO STATUS";

    /* Only add server threads if client is trusted */
    if (cinfo->trusted)
    {
      /* Create "ServerThreads" element */
      if (!(stlist = mxmlNewElement (xmldoc, "ServerThreads")))
      {
        lprintf (0, "[%s] Error adding child to XML INFO response", cinfo->hostname);
        errflag = 1;
      }

      /* Create a Thread element for each thread, lock thread list while looping */
      pthread_mutex_lock (&sthreads_lock);
      loopstp = sthreads;
      while (loopstp)
      {
        totalcount++;

        if (!(st = mxmlNewElement (stlist, "Thread")))
        {
          lprintf (0, "[%s] Error adding child to XML INFO response", cinfo->hostname);
          errflag = 1;
        }
        else
        {
          /* Add thread status flags to Thread element */
          string[0] = '\0';
          if (loopstp->td->td_flags & TDF_SPAWNING)
            strcat (string, " SPAWNING");
          if (loopstp->td->td_flags & TDF_ACTIVE)
            strcat (string, " ACTIVE");
          if (loopstp->td->td_flags & TDF_CLOSE)
            strcat (string, " CLOSE");
          if (loopstp->td->td_flags & TDF_CLOSING)
            strcat (string, " CLOSING");
          if (loopstp->td->td_flags & TDF_CLOSED)
            strcat (string, " CLOSED");
          mxmlElementSetAttr (st, "Flags", string);

          /* Determine server thread type and add specifics */
          if (loopstp->type == LISTEN_THREAD)
          {
            ListenPortParams *lpp = loopstp->params;
            char protocolstr[100];

            if (GenProtocolString (lpp->protocols, protocolstr, sizeof (protocolstr)) > 0)
              mxmlElementSetAttr (st, "Type", protocolstr);
            mxmlElementSetAttr (st, "Port", lpp->portstr);
          }
          else if (loopstp->type == MSEEDSCAN_THREAD)
          {
            MSScanInfo *mssinfo = loopstp->params;

            mxmlElementSetAttr (st, "Type", "miniSEED Scanner");
            mxmlElementSetAttr (st, "Directory", mssinfo->dirname);
            mxmlElementSetAttrf (st, "MaxRecursion", "%d", mssinfo->maxrecur);
            mxmlElementSetAttr (st, "StateFile", mssinfo->statefile);
            mxmlElementSetAttr (st, "Match", mssinfo->matchstr);
            mxmlElementSetAttr (st, "Reject", mssinfo->rejectstr);
            mxmlElementSetAttrf (st, "ScanTime", "%g", mssinfo->scantime);
            mxmlElementSetAttrf (st, "PacketRate", "%g", mssinfo->rxpacketrate);
            mxmlElementSetAttrf (st, "ByteRate", "%g", mssinfo->rxbyterate);
          }
          else
          {
            mxmlElementSetAttr (st, "Type", "Unknown Thread");
          }
        }

        loopstp = loopstp->next;
      }
      pthread_mutex_unlock (&sthreads_lock);

      /* Add thread count attribute to ServerThreads element */
      mxmlElementSetAttrf (stlist, "TotalServerThreads", "%d", totalcount);
    }
  } /* End of STATUS */
  else if (!strncasecmp (type, "STREAMS", 7))
  {
    mxml_node_t *streamlist, *stream;
    hptime_t hpnow;
    int selectedcount = 0;
    Stack *streams;
    RingStream *ringstream;

    lprintf (1, "[%s] Received INFO STREAMS request", cinfo->hostname);
    type = "INFO STREAMS";

    /* Create "StreamList" element and add attributes */
    if (!(streamlist = mxmlNewElement (xmldoc, "StreamList")))
    {
      lprintf (0, "[%s] Error adding child to XML INFO response", cinfo->hostname);
      errflag = 1;
    }

    /* Collect stream list */
    if ((streams = GetStreamsStack (cinfo->ringparams, cinfo->reader)))
    {
      /* Get current time */
      hpnow = HPnow ();

      /* Create a "Stream" element for each stream */
      while ((ringstream = (RingStream *)StackPop (streams)))
      {
        if (!(stream = mxmlNewElement (streamlist, "Stream")))
        {
          lprintf (0, "[%s] Error adding child to XML INFO response", cinfo->hostname);
          errflag = 1;
        }
        else
        {
          mxmlElementSetAttr (stream, "Name", ringstream->streamid);
          mxmlElementSetAttrf (stream, "EarliestPacketID", "%" PRId64, ringstream->earliestid);
          ms_hptime2mdtimestr (ringstream->earliestdstime, string, 1);
          mxmlElementSetAttr (stream, "EarliestPacketDataStartTime", string);
          ms_hptime2mdtimestr (ringstream->earliestdetime, string, 1);
          mxmlElementSetAttr (stream, "EarliestPacketDataEndTime", string);
          mxmlElementSetAttrf (stream, "LatestPacketID", "%" PRId64, ringstream->latestid);
          ms_hptime2mdtimestr (ringstream->latestdstime, string, 1);
          mxmlElementSetAttr (stream, "LatestPacketDataStartTime", string);
          ms_hptime2mdtimestr (ringstream->latestdetime, string, 1);
          mxmlElementSetAttr (stream, "LatestPacketDataEndTime", string);

          /* DataLatency value is the difference between the current time and the time of last sample in seconds */
          mxmlElementSetAttrf (stream, "DataLatency", "%.1f", (double)MS_HPTIME2EPOCH ((hpnow - ringstream->latestdetime)));
        }

        free (ringstream);
        selectedcount++;
      }

      /* Cleanup stream stack */
      StackDestroy (streams, free);
    }
    else
    {
      lprintf (0, "[%s] Error generating Stack of streams", cinfo->hostname);
      errflag = 1;
    }

    /* Add stream count attributes to StreamList element */
    mxmlElementSetAttrf (streamlist, "TotalStreams", "%d", cinfo->ringparams->streamcount);
    mxmlElementSetAttrf (streamlist, "SelectedStreams", "%d", selectedcount);

  } /* End of STREAMS */
  else if (!strncasecmp (type, "CONNECTIONS", 11))
  {
    mxml_node_t *connlist, *conn;
    hptime_t hpnow;
    int selectedcount = 0;
    int totalcount = 0;
    struct cthread *loopctp;
    ClientInfo *tcinfo;
    char *conntype;
    pcre *match = 0;
    const char *errptr;
    int erroffset;

    /* Check for trusted flag, required to access this resource */
    if (!cinfo->trusted)
    {
      lprintf (1, "[%s] INFO CONNECTIONS request from un-trusted client",
               cinfo->hostname);
      SendPacket (cinfo, "ERROR", "Access to CONNECTIONS denied", 0, 1, 1);

      if (xmldoc)
        mxmlRelease (xmldoc);

      return -1;
    }

    lprintf (1, "[%s] Received INFO CONNECTIONS request", cinfo->hostname);
    type = "INFO CONNECTIONS";

    /* Get current time */
    hpnow = HPnow ();

    /* Compile match expression supplied with request */
    if (matchexpr)
    {
      match = pcre_compile (matchexpr, 0, &errptr, &erroffset, NULL);
      if (errptr)
      {
        lprintf (0, "[%s] Error with pcre_compile: %s", cinfo->hostname, errptr);
        errflag = 1;
        matchexpr = 0;
      }
    }

    /* Create "ConnectionList" element */
    if (!(connlist = mxmlNewElement (xmldoc, "ConnectionList")))
    {
      lprintf (0, "[%s] Error adding child to XML INFO response", cinfo->hostname);
      errflag = 1;
    }

    /* Create a Connection element for each client, lock client list while looping */
    pthread_mutex_lock (&cthreads_lock);
    loopctp = cthreads;
    while (loopctp)
    {
      /* Skip if client thread is not in ACTIVE state */
      if (!(loopctp->td->td_flags & TDF_ACTIVE))
      {
        loopctp = loopctp->next;
        continue;
      }

      totalcount++;
      tcinfo = (ClientInfo *)loopctp->td->td_prvtptr;

      /* Check matching expression against the client address string (host:port) and client ID */
      if (match)
        if (pcre_exec (match, NULL, tcinfo->hostname, strlen (tcinfo->hostname), 0, 0, NULL, 0) &&
            pcre_exec (match, NULL, tcinfo->ipstr, strlen (tcinfo->ipstr), 0, 0, NULL, 0) &&
            pcre_exec (match, NULL, tcinfo->clientid, strlen (tcinfo->clientid), 0, 0, NULL, 0))
        {
          loopctp = loopctp->next;
          continue;
        }

      if (!(conn = mxmlNewElement (connlist, "Connection")))
      {
        lprintf (0, "[%s] Error adding child to XML INFO response", cinfo->hostname);
        errflag = 1;
      }
      else
      {
        /* Determine connection type */
        if (tcinfo->type == CLIENT_DATALINK)
        {
          if (tcinfo->websocket)
            conntype = "WebSocket DataLink";
          else
            conntype = "DataLink";
        }
        else if (tcinfo->type == CLIENT_SEEDLINK)
        {
          if (tcinfo->websocket)
            conntype = "WebSocket SeedLink";
          else
            conntype = "SeedLink";
        }
        else
        {
          conntype = "Unknown";
        }

        mxmlElementSetAttr (conn, "Type", conntype);
        mxmlElementSetAttr (conn, "Host", tcinfo->hostname);
        mxmlElementSetAttr (conn, "IP", tcinfo->ipstr);
        mxmlElementSetAttr (conn, "Port", tcinfo->portstr);
        mxmlElementSetAttr (conn, "ClientID", tcinfo->clientid);
        ms_hptime2mdtimestr (tcinfo->conntime, string, 1);
        mxmlElementSetAttr (conn, "ConnectionTime", string);
        mxmlElementSetAttrf (conn, "Match", "%s", (tcinfo->matchstr) ? tcinfo->matchstr : "");
        mxmlElementSetAttrf (conn, "Reject", "%s", (tcinfo->rejectstr) ? tcinfo->rejectstr : "");
        mxmlElementSetAttrf (conn, "StreamCount", "%d", tcinfo->streamscount);
        mxmlElementSetAttrf (conn, "PacketID", "%" PRId64, tcinfo->reader->pktid);
        ms_hptime2mdtimestr (tcinfo->reader->pkttime, string, 1);
        mxmlElementSetAttr (conn, "PacketCreationTime",
                            (tcinfo->reader->pkttime != HPTERROR) ? string : "-");
        ms_hptime2mdtimestr (tcinfo->reader->datastart, string, 1);
        mxmlElementSetAttr (conn, "PacketDataStartTime",
                            (tcinfo->reader->datastart != HPTERROR) ? string : "-");
        ms_hptime2mdtimestr (tcinfo->reader->dataend, string, 1);
        mxmlElementSetAttr (conn, "PacketDataEndTime",
                            (tcinfo->reader->dataend != HPTERROR) ? string : "-");
        mxmlElementSetAttrf (conn, "TXPacketCount", "%" PRId64, tcinfo->txpackets[0]);
        mxmlElementSetAttrf (conn, "TXPacketRate", "%.1f", tcinfo->txpacketrate);
        mxmlElementSetAttrf (conn, "TXByteCount", "%" PRId64, tcinfo->txbytes[0]);
        mxmlElementSetAttrf (conn, "TXByteRate", "%.1f", tcinfo->txbyterate);
        mxmlElementSetAttrf (conn, "RXPacketCount", "%" PRId64, tcinfo->rxpackets[0]);
        mxmlElementSetAttrf (conn, "RXPacketRate", "%.1f", tcinfo->rxpacketrate);
        mxmlElementSetAttrf (conn, "RXByteCount", "%" PRId64, tcinfo->rxbytes[0]);
        mxmlElementSetAttrf (conn, "RXByteRate", "%.1f", tcinfo->rxbyterate);

        /* Latency value is the difference between the current time and the time of last packet exchange in seconds */
        mxmlElementSetAttrf (conn, "Latency", "%.1f", (double)MS_HPTIME2EPOCH ((hpnow - tcinfo->lastxchange)));

        if (tcinfo->reader->pktid <= 0)
          strncpy (string, "-", sizeof (string));
        else
          snprintf (string, sizeof (string), "%d", tcinfo->percentlag);

        mxmlElementSetAttr (conn, "PercentLag", string);

        selectedcount++;
      }

      loopctp = loopctp->next;
    }
    pthread_mutex_unlock (&cthreads_lock);

    /* Add client count attribute to ConnectionList element */
    mxmlElementSetAttrf (connlist, "TotalConnections", "%d", totalcount);
    mxmlElementSetAttrf (connlist, "SelectedConnections", "%d", selectedcount);

    /* Free compiled match expression */
    if (match)
      pcre_free (match);

  } /* End of CONNECTIONS */
  /* Unrecognized INFO request */
  else
  {
    lprintf (0, "[%s] Unrecognized INFO request type: %s", cinfo->hostname, type);
    snprintf (string, sizeof (string), "Unrecognized INFO request type: %s", type);
    SendPacket (cinfo, "ERROR", string, 0, 1, 1);
    errflag = 2;
  }

  /* Send ERROR to client if not already done */
  if (errflag == 1)
  {
    SendPacket (cinfo, "ERROR", "Error processing INFO request", 0, 1, 1);
  }
  /* Convert to XML string and send to client */
  else if (xmldoc && !errflag)
  {
    /* Do not wrap the output XML */
    mxmlSetWrapMargin (0);

    /* Convert to XML string */
    if (!(xmlstr = mxmlSaveAllocString (xmldoc, MXML_NO_CALLBACK)))
    {
      lprintf (0, "[%s] Error with mxmlSaveAllocString()", cinfo->hostname);
      if (xmldoc)
        mxmlRelease (xmldoc);
      return -1;
    }

    /* Trim final newline character if present */
    xmllength = strlen (xmlstr);
    if (xmlstr[xmllength - 1] == '\n')
    {
      xmlstr[xmllength - 1] = '\0';
      xmllength--;
    }

    /* Send XML to client */
    if (SendPacket (cinfo, type, xmlstr, 0, 0, 1))
    {
      if (cinfo->socketerr != 2)
        lprintf (0, "[%s] Error sending INFO XML", cinfo->hostname);

      if (xmldoc)
        mxmlRelease (xmldoc);
      if (xmlstr)
        free (xmlstr);
      return -1;
    }
  }

  /* Free allocated memory */
  if (xmldoc)
    mxmlRelease (xmldoc);

  if (xmlstr)
    free (xmlstr);

  return (cinfo->socketerr || errflag) ? -1 : 0;
} /* End of HandleInfo */

/***************************************************************************
 * SendPacket:
 *
 * Create and send a packet from given header and packet data strings.
 * The header and packet strings must be NULL-terminated.  If the data
 * argument is NULL a header-only packet will be send.  If the
 * addvalue argument is true the value argument will be appended to
 * the header.  If the addsize argument is true the size of the packet
 * string will be appended to the header.
 *
 * Returns 0 on success and -1 on error.
 ***************************************************************************/
static int
SendPacket (ClientInfo *cinfo, char *header, char *data,
            int64_t value, int addvalue, int addsize)
{
  char *wirepacket = 0;
  char headerstr[255];
  int headerlen;
  int datalen;

  if (!cinfo || !header)
    return -1;

  /* Determine length of packet data string */
  datalen = (data) ? strlen (data) : 0;

  /* Add value and/or size of packet data to header */
  if (addvalue || addsize)
  {
    if (addvalue && addsize)
      snprintf (headerstr, sizeof (headerstr), "%s %" PRId64 " %u", header, value, datalen);
    else if (addvalue)
      snprintf (headerstr, sizeof (headerstr), "%s %" PRId64, header, value);
    else
      snprintf (headerstr, sizeof (headerstr), "%s %u", header, datalen);

    header = headerstr;
  }

  /* Determine length of header and sanity check it */
  headerlen = strlen (header);

  if (headerlen > 255)
  {
    lprintf (0, "[%s] SendPacket(): Header length is too large: %d",
             cinfo->hostname, headerlen);
    return -1;
  }

  /* Use the send buffer if large enough otherwise allocate memory for wire packet */
  if (cinfo->sendbuflen >= (3 + headerlen + datalen))
  {
    wirepacket = cinfo->sendbuf;
  }
  else
  {
    if (!(wirepacket = (char *)malloc (3 + headerlen + datalen)))
    {
      lprintf (0, "[%s] SendPacket(): Error allocating wire packet buffer",
               cinfo->hostname);
      return -1;
    }
  }

  /* Populate pre-header sequence of wire packet */
  wirepacket[0] = 'D';
  wirepacket[1] = 'L';
  wirepacket[2] = (uint8_t)headerlen;

  /* Copy header and packet data into wire packet */
  memcpy (&wirepacket[3], header, headerlen);

  if (data)
    memcpy (&wirepacket[3 + headerlen], data, datalen);

  /* Send complete wire packet */
  if (SendData (cinfo, wirepacket, (3 + headerlen + datalen)))
  {
    if (cinfo->socketerr != 2)
      lprintf (0, "[%s] SendPacket(): Error sending packet: %s",
               cinfo->hostname, strerror (errno));
    return -1;
  }

  /* Free the wire packet space if we allocated it */
  if (wirepacket && wirepacket != cinfo->sendbuf)
    free (wirepacket);

  return 0;
} /* End of SendPacket() */

/***************************************************************************
 * SendRingPacket:
 *
 * Create a packet header for a RingPacket and send() the header and
 * the packet data to the client.  Upon success update the client
 * transmission counts.
 *
 * The packet header is: "DL<size>PACKET <streamid> <pktid> <hppackettime> <hpdatastart> <hpdataend> <size>"
 *
 * Returns 0 on success and -1 on error.
 ***************************************************************************/
static int
SendRingPacket (ClientInfo *cinfo)
{
  StreamNode *stream;
  char header[255];
  int headerlen;
  int newstream = 0;

  if (!cinfo)
    return -1;

  /* Create packet header: "PACKET <streamid> <pktid> <hppackettime> <hpdatatime> <size>" */
  headerlen = snprintf (header, sizeof (header),
                        "PACKET %s %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %u",
                        cinfo->packet.streamid, cinfo->packet.pktid, cinfo->packet.pkttime,
                        cinfo->packet.datastart, cinfo->packet.dataend, cinfo->packet.datasize);

  /* Sanity check header length */
  if (headerlen > 255)
  {
    lprintf (0, "[%s] SendRingPacket(): Header length is too large: %d",
             cinfo->hostname, headerlen);
    return -1;
  }

  /* Make sure send buffer is large enough for wire packet */
  if (cinfo->sendbuflen < (3 + headerlen + cinfo->packet.datasize))
  {
    lprintf (0, "[%s] SendRingPacket(): Send buffer not large enough (%d bytes), need %d bytes",
             cinfo->hostname, cinfo->sendbuflen, 3 + headerlen + cinfo->packet.datasize);
    return -1;
  }

  /* Populate pre-header sequence of wire packet */
  cinfo->sendbuf[0] = 'D';
  cinfo->sendbuf[1] = 'L';
  cinfo->sendbuf[2] = (uint8_t)headerlen;

  /* Copy header and packet data into wire packet */
  memcpy (&cinfo->sendbuf[3], header, headerlen);

  memcpy (&cinfo->sendbuf[3 + headerlen], cinfo->packetdata, cinfo->packet.datasize);

  /* Send complete wire packet */
  if (SendData (cinfo, cinfo->sendbuf, (3 + headerlen + cinfo->packet.datasize)))
  {
    if (cinfo->socketerr != 2)
      lprintf (0, "[%s] SendRingPacket(): Error sending packet: %s",
               cinfo->hostname, strerror (errno));
    return -1;
  }

  /* Get (creating if needed) the StreamNode for this streamid */
  if ((stream = GetStreamNode (cinfo->streams, &cinfo->streams_lock,
                               cinfo->packet.streamid, &newstream)) == 0)
  {
    lprintf (0, "[%s] Error with GetStreamNode for %s",
             cinfo->hostname, cinfo->packet.streamid);
    return -1;
  }

  if (newstream)
  {
    lprintf (3, "[%s] New stream for client: %s", cinfo->hostname, cinfo->packet.streamid);
    cinfo->streamscount++;
  }

  /* Update StreamNode packet and byte counts */
  pthread_mutex_lock (&(cinfo->streams_lock));
  stream->txpackets++;
  stream->txbytes += cinfo->packet.datasize;
  pthread_mutex_unlock (&(cinfo->streams_lock));

  /* Update client transmit and counts */
  cinfo->txpackets[0]++;
  cinfo->txbytes[0] += cinfo->packet.datasize;

  /* Update last sent packet ID */
  cinfo->lastid = cinfo->packet.pktid;

  return 0;
} /* End of SendRingPacket() */

/***************************************************************************
 * SelectedStreams:
 *
 * Determine the number of streams selected with the current match and
 * reject settings.  Since GetStreamsStack() already applies the match
 * and reject expressions the only thing left to do is count the
 * select streams returned.
 *
 * Returns selected stream count on success and -1 on error.
 ***************************************************************************/
static int
SelectedStreams (RingParams *ringparams, RingReader *reader)
{
  Stack *streams;
  RingStream *ringstream;
  int streamcnt = 0;

  if (!ringparams || !reader)
    return -1;

  /* Create a duplicate Stack of currently selected RingStreams */
  streams = GetStreamsStack (ringparams, reader);

  /* Count the selected streams */
  while ((ringstream = StackPop (streams)))
  {
    free (ringstream);
    streamcnt++;
  }

  /* Cleanup stream stack */
  StackDestroy (streams, free);

  return streamcnt;
} /* End of SelectedStreams() */
