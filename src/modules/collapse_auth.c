/**
 * Compile via
 * make custommodule MODULEFILE=collapse_auth
 */
#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "proto.h"
#include "channel.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "h.h"
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif

#include <curl/curl.h>

#define DEF_MESSAGE		"Authentication failed"
#define DelHook(x)		if (x) HookDel(x); x = NULL

/**
 * Executed before client connection is completed
 */
static Hook *HookPreConnect;
// static Hook *HookConfRun;

static int  collapse_auth(aClient *cptr, aClient *sptr, int parc, char *parv[]);
static int	cb_test(ConfigFile *, ConfigEntry *, int, int *);
static int	cb_pre_connect(aClient *);
static int	cb_conf(ConfigFile *, ConfigEntry *, int);

static long SNO_USERAUTH = 0;

// DLLFUNC CMD_FUNC(collapse_auth);

#define MSG_USERAUTH 	"USERAUTH"	
#define TOK_USERAUTH 	"UA"	

ModuleHeader MOD_HEADER(collapse_auth)
  = {
    "collapse_auth",
    "$Id$",
    "user authentication via collapse.io", 
    "3.2-b8-1",
    NULL 
  };

DLLFUNC int MOD_INIT(collapse_auth)(ModuleInfo *modinfo)
{
  CommandAdd(modinfo->handle, MSG_USERAUTH, TOK_USERAUTH, collapse_auth, MAXPARA, M_USER|M_SERVER);
  MARK_AS_OFFICIAL_MODULE(modinfo);

  HookPreConnect	= HookAddEx(modinfo->handle, HOOKTYPE_PRE_LOCAL_CONNECT, cb_pre_connect);
  // HookConfRun	= HookAddEx(modinfo->handle, HOOKTYPE_CONFIGRUN, cb_conf);

  return MOD_SUCCESS;
}

DLLFUNC int MOD_TEST(collapse_auth)(ModuleInfo *modinfo)
{
  return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(collapse_auth)(int module_load)
{
  return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(collapse_auth)(int module_unload)
{
  DelHook(HookPreConnect);
  // DelHook(HookConfRun);

  return MOD_SUCCESS;
}

static int authentication_status(char *login, char *pass) {
  CURL *curl = curl_easy_init();
  CURLcode res;
  long http_code = 0;

  size_t length = (strlen(login) + strlen(pass) + 2);
  char *creds = malloc(length * sizeof(char));

  snprintf(creds, length, "%s:%s", login, pass); 

  curl_easy_setopt(curl, CURLOPT_URL,
                   "http://localhost:8090/api/auth");
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 45);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15);
  curl_easy_setopt(curl, CURLOPT_USERPWD, creds);

  res = curl_easy_perform(curl);

  if (res == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
  }

  return http_code;
}

static u_int do_client_auth(aClient *sptr) {
  char tmp[PASSWDLEN+1], *login, *passwd;
  char *realhost, *nuip;
  int authenticationStatus = 0;

  if (BadPtr(sptr->passwd)) {
    sendto_snomask(SNO_USERAUTH, "*** Failed authentication by %s!%s@%s -- "
                   "no password given",
                   sptr->name, sptr->user->username, sptr->user->realhost);
    ircd_log(LOG_CLIENT, "Failed authentication by %s!%s@%s -- "
             "no password given",
             sptr->name, sptr->user->username, sptr->user->realhost);
    // return 0;
    return 1;
  }

  login = sptr->user->username;
  passwd = sptr->passwd;

  authenticationStatus =
    authentication_status(login, passwd);

  if (sptr->passwd) {
    MyFree(sptr->passwd);
    sptr->passwd = NULL;
  }

  if(200 != authenticationStatus) {
    ircd_log(LOG_CLIENT, "Failed authentication by %s!%s@%s -- "
             "Authentication Failed",
             sptr->name, sptr->user->username, sptr->user->realhost);
    // return 0;
    return 1;
  }

  ircd_log(LOG_CLIENT, "Successful authentication by %s!%s@%s with username %s",
           sptr->name, sptr->user->username, sptr->user->realhost, login);

  return 1;
}

static int cb_pre_connect(aClient *sptr) {
  if (!do_client_auth(sptr)) {
    return exit_client(sptr, sptr, &me, DEF_MESSAGE);
  }

  return 0;
}

static int cb_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
  return 0;
}

static int cb_conf(ConfigFile *cf, ConfigEntry *ce, int type) {
}

static int collapse_auth(aClient *cptr, aClient *sptr, int parc, char *parv[]) {
  return 0;
}

