/*
 * ==================================================================
 * Filename:             userauth.c
 * Description:          Extended user authentication system
 * Written by:           AngryWolf <angrywolf@flashmail.com>
 * Documentation:        userauth.txt (comes with the package)
 * ==================================================================
 */

#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <fcntl.h>
#include "h.h"
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif

typedef struct _authline AuthLine;

struct _authline
{
	AuthLine		*prev, *next;
	char			*login;
	anAuthStruct		*auth;
};

extern void			sendto_one(aClient *to, char *pattern, ...);
extern void			sendto_realops(char *pattern, ...);
extern ConfigEntry		*config_find_entry(ConfigEntry *, char *);
#ifdef USE_LIBCURL
extern char			*download_file(char *url, char **error);
extern void			download_file_async(char *url, time_t cachetime, vFP callback);
extern char			*url_getfilename(char *url);
extern int			url_is_valid(char *string);
#endif
extern anAuthStruct		AuthTypes[];

#define FlagUA			'U'
#define SnomaskUA		'a'
#define MSG_USERAUTH		"USERAUTH"
#define TOK_USERAUTH		"UA"
#define DEF_MESSAGE		"Authentication failed"
#define ERR_GUEST		":%s 499 %s :Guests are not allowed to change nickname"
#define MAX_LINESIZE		255

#define ircstrdup(x,y)  	if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y)
#define ircfree(x)		if (x) MyFree(x); x = NULL
#define IsParam(x)		(parc > (x) && !BadPtr(parv[(x)]))
#define IsNotParam(x)		(parc <= (x) || BadPtr(parv[(x)]))
#define DelSnomask(x)		if (x) SnomaskDel(x); x = NULL
#define DelHook(x)		if (x) HookDel(x); x = NULL
#define DelVflag(x)		if (x) VersionflagDel(x, MyMod); x = NULL
#define DelCommand(x)		if (x) CommandDel(x); x = NULL

#define FLAGS_GUEST		0x20000000 /* This is the 4th unoccupied flag in Unreal3.2-beta18 */
#define IsGuest(x)		((x)->flags & FLAGS_GUEST)
#define SetGuest(x)		((x)->flags |= FLAGS_GUEST)
#define ClearGuest(x)		((x)->flags &= ~FLAGS_GUEST)

#ifdef GUEST
static Cmdoverride		*AddOverride(char *msg, iFP cb);
static int			override_nick(Cmdoverride *, aClient *, aClient *, int, char *[]);

static Cmdoverride		*OvrNick;
static aCommand			*CmdGuest;
#endif

static Command			*AddCommand(Module *module, char *msg, char *token, iFP func);
static Snomask			*AddSnomask(Module *module, char flag, iFP allowed, long *mode);
static int			m_userauth(aClient *cptr, aClient *sptr, int parc, char *parv[]);
static int			cb_test(ConfigFile *, ConfigEntry *, int, int *);
static int			cb_conf(ConfigFile *, ConfigEntry *, int);
static int			cb_posttest(int *);
static int			cb_rehash();
static int			cb_rehash_complete();
static void			cb_stats(aClient *sptr);
static int			cb_pre_connect(aClient *);
static int			cb_rehashflag(aClient *, aClient *, char *);

static u_int			read_authfile(char *path, char *file);
#ifdef USE_LIBCURL
static int			download_authfile(ConfigEntry *ce);
static void			download_authfile_complete(char *url, char *file, char *errorbuf, int cached);
#endif

#ifndef STATIC_LINKING
static Versionflag		*UserAuthFlag = NULL;
#endif
static Command			*CmdUserauth = NULL;
static Snomask			*UserAuthSnomask = NULL;
static AuthLine			*AuthLines = NULL;
static ConfigItem_except	*AuthExceptions = NULL, *PasswordedHosts = NULL;
static long			SNO_USERAUTH = 0;
static Hook			*HookConfTest, *HookConfRun, *HookPostTest, *HookConfRehash;
static Hook			*HookRehashFlag, *HookPreConnect, *HookRehashDone;
static u_short			module_loaded = 0;

static struct
{
	unsigned		enable : 1;
	unsigned		enable_logging : 1;
	unsigned		use_client_username : 1;
	unsigned		disable_command : 1;
	unsigned		allow_guests : 1;
	char			*authfile;
	char			*message;
} Settings;

struct
{
	unsigned		authfile : 1;
} ReqConf;

#ifdef USE_LIBCURL
struct {
	unsigned		is_url : 1;
	unsigned		once_completed : 1;
	unsigned		in_progress : 1;
	char			*file;			// File name
	char			*path;			// File path
	char			*url;			// Full URL address
} Download;
#endif

#ifndef STATIC_LINKING
static ModuleInfo		*MyModInfo;
 #define MyMod			MyModInfo->handle
 #define SAVE_MODINFO		MyModInfo = modinfo;
#else
 #define MyMod			NULL
 #define SAVE_MODINFO
#endif

/* ================================================================= */

ModuleHeader MOD_HEADER(userauth)
  = {
	"userauth",
	"$Id: userauth.c,v 5.4 2004/10/03 13:30:10 angrywolf Exp $",
	"extended user authentication system",
	"3.2-b8-1",
	NULL
    };

/* ================================================================= */

#ifdef GUEST
Cmdoverride *AddOverride(char *msg, iFP cb)
{
	Cmdoverride *ovr = CmdoverrideAdd(MyMod, msg, cb);

#ifndef STATIC_LINKING
        if (ModuleGetError(MyMod) != MODERR_NOERROR || !ovr)
#else
        if (!ovr)
#endif
	{
#ifndef STATIC_LINKING
		config_error("Error replacing command %s when loading module %s: %s",
			msg, MOD_HEADER(userauth).name, ModuleGetErrorStr(MyMod));
#else
		config_error("Error replacing command %s when loading module %s",
			msg, MOD_HEADER(userauth).name);
#endif
		return NULL;
	}

	return ovr;
}
#endif

static Command *AddCommand(Module *module, char *msg, char *token, iFP func)
{
	Command *cmd;

	if (CommandExists(msg))
    	{
		config_error("Command %s already exists", msg);
		return NULL;
    	}
    	if (CommandExists(token))
	{
		config_error("Token %s already exists", token);
		return NULL;
    	}

	cmd = CommandAdd(module, msg, token, func, MAXPARA, 0);

#ifndef STATIC_LINKING
	if (ModuleGetError(module) != MODERR_NOERROR || !cmd)
#else
	if (!cmd)
#endif
	{
#ifndef STATIC_LINKING
		config_error("Error adding command %s: %s", msg,
			ModuleGetErrorStr(module));
#else
		config_error("Error adding command %s", msg);
#endif
		return NULL;
	}

	return cmd;
}

static Snomask *AddSnomask(Module *module, char flag, iFP allowed, long *mode)
{
        Snomask *s;

        *mode = 0;
        s = SnomaskAdd(module, flag, allowed, mode);

#ifndef STATIC_LINKING
        if ((ModuleGetError(module) != MODERR_NOERROR) || !s)
#else
        if (!s)
#endif
        {
#ifndef STATIC_LINKING
                sendto_realops("[\2userauth\2] Error adding snomask %c: %s",
                        flag, ModuleGetErrorStr(module));
#else
                sendto_realops("[\2userauth\2] Error adding snomask %c",
                        flag);
#endif
                return NULL;
        }

        return s;
}

/* ================================================================= */

/*
 * Auth_MyCheckError:
 *	This makes sure that password and authtype are valid
 *      this is a modified version of Auth_CheckError from src/auth.c
 */

int Auth_MyCheckError(u_long line, char *password, char *authtype)
{
	short type = AUTHTYPE_PLAINTEXT;
#ifdef AUTHENABLE_SSL_CLIENTCERT
	X509 *x509_filecert = NULL;
	FILE *x509_f = NULL;
#endif
	if (authtype)
	{
		if ((type = Auth_FindType(authtype)) == -1)
		{
			config_error("%s:%ld: authentication module failure: %s is not an implemented/enabled authentication method",
				Settings.authfile, line, authtype);
			return -1;
		}
	}

	switch (type)
	{
#ifdef AUTHENABLE_UNIXCRYPT
		case AUTHTYPE_UNIXCRYPT:
			/* If our data is like 1 or none, we just let em through .. */
			if (strlen(password) < 2)
			{
				config_error("%s:%ld: authentication module failure: AUTHTYPE_UNIXCRYPT: no salt (crypt strings will always be >2 in length)",
					Settings.authfile, line);
				return -1;
			}
			break;
#endif
#ifdef AUTHENABLE_SSL_CLIENTCERT
		case AUTHTYPE_SSL_CLIENTCERT:
			if (!(x509_f = fopen(password, "r")))
			{
				config_error("%s:%ld: authentication module failure: AUTHTYPE_SSL_CLIENTCERT: error opening file %s: %s",
					Settings.authfile, line, password, strerror(errno));
					return -1;
				}
				x509_filecert = PEM_read_X509(x509_f, NULL, NULL, NULL);
				fclose(x509_f);
				if (!x509_filecert)
				{
					config_error("%s:%ld: authentication module failure: AUTHTYPE_SSL_CLIENTCERT: PEM_read_X509 errored in file %s (format error?)",
							Settings.authfile, line, password);
					return -1;
				}
				X509_free(x509_filecert);
				break;
#endif
		default: ;
	}

	return 1;
}

/*
 * Auth_MyConvert:
 *      this is a modified version of Auth_Convert from src/auth.c
 */

anAuthStruct *Auth_MyConvert(char *password, char *authtype)
{
        anAuthStruct *as;

        as = (anAuthStruct *) MyMalloc(sizeof(anAuthStruct));
        as->data = strdup(password);
	as->type = authtype ? Auth_FindType(authtype) : AUTHTYPE_PLAINTEXT;

        return as;
}

/*
 * Auth_FindName:
 *	Finds an authentication method name (used by /confoper)
 */

char *Auth_FindName(short type)
{
        anAuthStruct *p;

	for (p = AuthTypes; p->data; p++)
		if (p->type == type)
			return p->data;

	return NULL;
}


static AuthLine *MakeAuthLine(char *login, char *password, char *authtype)
{
	AuthLine *l;

	l = (AuthLine *) MyMallocEx(sizeof(AuthLine));
	l->login = strdup(login);
	l->auth = Auth_MyConvert(password, authtype);

	return l;
}

static void FreeAuthLines(AuthLine *list)
{
	AuthLine	*l;
	ListStruct	*next;

	for (l = list; l; l = (AuthLine *) next)
	{
		next = (ListStruct *) l->next;
		DelListItem(l, list);
		MyFree(l->login);
		Auth_DeleteAuthStruct(l->auth);
		MyFree(l);
	}
}

static void AddAuthException(char *mask)
{
	ConfigItem_except *e;

	e = (ConfigItem_except *) MyMallocEx(sizeof(ConfigItem_except));
	e->mask = strdup(mask);

	AddListItem(e, AuthExceptions);
}

static void AddPasswordedHost(char *mask)
{
	ConfigItem_except *e;

	e = (ConfigItem_except *) MyMallocEx(sizeof(ConfigItem_except));
	e->mask = strdup(mask);

	AddListItem(e, PasswordedHosts);
}

AuthLine *FindAuthLine(char *login)
{
	AuthLine *l;

	for (l = AuthLines; l; l = l->next)
		if (!strcmp(l->login, login))
			break;
	return l;
}

static void make_hosts(aClient *cptr, char **p_realhost, char **p_nuip)
{
	char		*s;
	static char	realhost[NICKLEN + USERLEN + HOSTLEN + 6];
	static char	nuip[NICKLEN + USERLEN + HOSTLEN + 6];

	memset(&realhost, 0, sizeof realhost);
	memset(&nuip, 0, sizeof nuip);

	s = make_user_host(cptr->user->username, cptr->user->realhost);
	strlcpy(realhost, s, sizeof realhost);

	s = make_user_host(cptr->user->username, Inet_ia2p(&cptr->ip));
	strlcpy(nuip, s, sizeof nuip);

	*p_realhost	= realhost;
	*p_nuip		= nuip;
}

ConfigItem_except *Find_except_userauth(char *realhost, char *nuip)
{
	ConfigItem_except *e;

	for (e = AuthExceptions; e; e = (ConfigItem_except *) e->next)
		if (!match(e->mask, realhost) || !match(e->mask, nuip))
			break;

	return e;
}

ConfigItem_except *Find_passworded_userhost(char *realhost, char *nuip)
{
	ConfigItem_except *e;

	for (e = PasswordedHosts; e; e = (ConfigItem_except *) e->next)
		if (!match(e->mask, realhost) || !match(e->mask, nuip))
			break;

	return e;
}

// =================================================================
// Authfile
// =================================================================

u_int read_authfile(char *path, char *file)
{
	AuthLine	*l, *Temp = NULL;
	int		fd, i;
	char		*login = NULL, *password = NULL, *authtype = NULL;
	char		line[MAX_LINESIZE + 1], *tmp;
	u_long		linenum = 0;
	u_int		error = 0;

	if ((fd = open(path, O_RDONLY)) == -1)
	{
		config_error("Error opening file %s: %s",
			path, strerror(errno));
                return 0;
	}

	/* make sure buffer is at empty pos */
	(void) dgets(-1, NULL, 0);

	while ((i = dgets(fd, line, MAX_LINESIZE)) > 0)
        {
		linenum++;

		line[i] = '\0';
		if (line[0] == '#')
			continue;
		if ((tmp = (char *) strchr(line, '\n')))
                        *tmp = '\0';
                if ((tmp = (char *) strchr(line, '\r')))
                        *tmp = '\0';

		login = strtok(line, ":");
		if (!login)
			continue;
		password = strtok(NULL, ":");
		if (!password)
		{
			config_error("%s:%ld: Missing password",
				file, linenum);
			error = 1;
			break;
		}
		authtype = strtok(NULL, ":");
		if (Auth_MyCheckError(linenum, password, authtype) < 0)
		{
			error = 1;
			break;
		}
		l = MakeAuthLine(login, password, authtype);
		AddListItem(l, Temp);
        }

	close(fd);

	if (error)
		FreeAuthLines(Temp);
	else
	{
		if (AuthLines)
			FreeAuthLines(AuthLines);
		AuthLines = Temp;
	}

        return !error;
}

#ifdef USE_LIBCURL
static void remove_authfile()
{
	if (Download.path)
	{
		if (remove(Download.path) == -1)
		{
			if (config_verbose > 0)
				config_status("Cannot remove file %s: %s",
					Download.path, strerror(errno));
		}
	        MyFree(Download.path);
	        Download.path = NULL;
	}
}

static int download_authfile(ConfigEntry *ce)
{
	int		ret = 0;
	struct stat	sb;
	char		*file, *filename;

	if (Download.in_progress)
		return 0;

	Download.is_url = 1;
	ircstrdup(Download.url, ce->ce_vardata);

	file = url_getfilename(ce->ce_vardata);
	filename = unreal_getfilename(file);
	ircstrdup(Download.file, filename);
	MyFree(file);

	if (!loop.ircd_rehashing && !Download.once_completed)
	{
		char *error;

		if (config_verbose > 0)
			config_status("Downloading %s", Download.url);

		if (!(file = download_file(ce->ce_vardata, &error)))
		{
			config_error("%s:%i: test: error downloading '%s': %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				ce->ce_vardata, error);
			return -1;
		}

		Download.once_completed = 1;
		ircstrdup(Download.path, file);
		read_authfile(Download.path, Download.file);

		MyFree(file);
		return 0;
	}

	file = Download.path ? Download.path : Download.file;

	if ((ret = stat(file, &sb)) && errno != ENOENT)
	{
		/* I know, stat shouldn't fail... */
		config_error("%s:%i: could not get the creation time of %s: stat() returned %d: %s",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
			Download.file, ret, strerror(errno));
		return -1;
	}

	if (config_verbose > 0)
		config_status("Downloading %s", Download.url);

	Download.in_progress = 1;
	download_file_async(Download.url, sb.st_ctime, download_authfile_complete);

	return 0;
}

static void download_authfile_complete(char *url, char *file, char *errorbuf, int cached)
{
	Download.in_progress = 0;
	Download.once_completed = 1;

	if (!cached)
	{
		if (!file)
		{
			config_error("Error downloading %s: %s",
				url, errorbuf);
			return;
		}

		remove_authfile();
		Download.path = strdup(file);
		read_authfile(Download.path, Download.file);
	}
	else
        {
                char *urlfile = url_getfilename(url);
                char *file = unreal_getfilename(urlfile);
                char *tmp = unreal_mktemp("tmp", file);

                unreal_copyfile(Download.path, tmp);
		remove_authfile();
		Download.path = strdup(tmp);
                MyFree(urlfile);
        }
}
#endif

// =================================================================
// Functions related to loading/unloading configuration
// =================================================================

static void InitConf()
{
	memset(&Settings, 0, sizeof(Settings));
	memset(&ReqConf, 0, sizeof(ReqConf));

	AuthLines	= NULL;
	AuthExceptions	= NULL;
	PasswordedHosts	= NULL;
}

static void FreeConf()
{
	ConfigItem_except	*e;
	ListStruct 		*next;

	for (e = AuthExceptions; e; e = (ConfigItem_except *) next)
	{
		next = (ListStruct *) e->next;
		DelListItem(e, AuthExceptions);
		MyFree(e->mask);
		MyFree(e);
	}
	for (e = PasswordedHosts; e; e = (ConfigItem_except *) next)
	{
		next = (ListStruct *) e->next;
		DelListItem(e, PasswordedHosts);
		MyFree(e->mask);
		MyFree(e);
	}

	if (Settings.authfile)
		MyFree(Settings.authfile);
	if (Settings.message)
		MyFree(Settings.message);

	FreeAuthLines(AuthLines);
	DelCommand(CmdUserauth);
#ifdef GUEST
	if (OvrNick)
		CmdoverrideDel(OvrNick);
#endif
}

// =================================================================
// Module functions
// =================================================================

DLLFUNC int MOD_TEST(userauth)(ModuleInfo *modinfo)
{
	SAVE_MODINFO

	HookConfTest	= HookAddEx(modinfo->handle, HOOKTYPE_CONFIGTEST, cb_test);
	HookPostTest	= HookAddEx(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, cb_posttest);

	return MOD_SUCCESS;
}

DLLFUNC int MOD_INIT(userauth)(ModuleInfo *modinfo)
{
	SAVE_MODINFO

#ifndef STATIC_LINKING
	ModuleSetOptions(modinfo->handle, MOD_OPT_PERM);
#endif
	InitConf();

#ifdef USE_LIBCURL
	memset(&Download, 0, sizeof(Download));
#endif
	CmdUserauth	= NULL;
#ifdef GUEST
	OvrNick		= NULL;
	CmdGuest	= NULL;
#endif
		
        UserAuthSnomask	= AddSnomask(modinfo->handle, SnomaskUA, umode_allow_opers, &SNO_USERAUTH);
	HookConfRun	= HookAddEx(modinfo->handle, HOOKTYPE_CONFIGRUN, cb_conf);
	HookConfRehash	= HookAddEx(modinfo->handle, HOOKTYPE_REHASH, cb_rehash);
	HookRehashDone	= HookAddEx(modinfo->handle, HOOKTYPE_REHASH_COMPLETE, cb_rehash_complete);
	HookRehashFlag	= HookAddEx(modinfo->handle, HOOKTYPE_REHASHFLAG, cb_rehashflag);
	HookPreConnect	= HookAddEx(modinfo->handle, HOOKTYPE_PRE_LOCAL_CONNECT, cb_pre_connect);

#ifndef STATIC_LINKING
	UserAuthFlag	= VersionflagAdd(modinfo->handle, FlagUA);
#endif

	if (!UserAuthSnomask)
		return MOD_FAILED;

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(userauth)(int module_load)
{
	cb_rehash_complete();
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(userauth)(int module_unload)
{
	FreeConf();

	DelHook(HookPreConnect);
	DelHook(HookRehashFlag);
	DelHook(HookRehashDone);
	DelHook(HookConfRehash);
	DelHook(HookConfRun);
	DelHook(HookPostTest);
	DelHook(HookConfTest);

#ifndef STATIC_LINKING
	DelVflag(UserAuthFlag);
#endif
	DelSnomask(UserAuthSnomask);

#ifdef USE_LIBCURL
	ircfree(Download.path);
    	ircfree(Download.file);
	ircfree(Download.url);
#endif

	return 0;
}

// =================================================================
// Config file interfacing
// =================================================================

static int cb_rehash()
{
	module_loaded = 0;
	FreeConf();
	InitConf();

	return 1;
}

static int cb_rehash_complete()
{
	if (!module_loaded)
	{
		if (!Settings.disable_command)
			CmdUserauth = AddCommand(MyMod, MSG_USERAUTH,
				TOK_USERAUTH, m_userauth);

#ifdef GUEST
		OvrNick = AddOverride("nick", override_nick);

		if (!(CmdGuest = find_Command_simple("guest")))
			/* This should not happen */
			config_error("command GUEST not found, "
				"userauth::allow-guests disabled");
#endif
		module_loaded = 1;
	}
        return 1;
}

#define CHECK_EMPTY(ce, parent) \
		if (!(ce)->ce_varname) \
		{ \
			config_error("%s:%i: blank %s item", \
				(ce)->ce_fileptr->cf_filename, \
				(ce)->ce_varlinenum, (parent)->ce_varname); \
			errors++; \
			continue; \
		} \
		if (!(ce)->ce_vardata) \
		{ \
			config_error("%s:%i: %s::%s without value", \
				(ce)->ce_fileptr->cf_filename, \
				(ce)->ce_varlinenum, \
				(parent)->ce_varname, (ce)->ce_varname); \
			errors++; \
			continue; \
		}

static int cb_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	ConfigEntry	*cep, *cepp;
	int		errors = 0;
#ifdef USE_LIBCURL
	char		*file = NULL, *filename = NULL;
#endif

	if (type == CONFIG_MAIN)
	{
		if (!strcmp(ce->ce_varname, "userauth"))
		{
			for (cep = ce->ce_entries; cep; cep = cep->ce_next)
			{
				CHECK_EMPTY(cep, ce)

				if (!strcmp(cep->ce_varname, "file"))
				{
#ifdef USE_LIBCURL
					if (url_is_valid(cep->ce_vardata))
					{
						if (!(file = url_getfilename(cep->ce_vardata)) || !(filename = unreal_getfilename(file)))
						{
							config_error("%s:%i: invalid filename in URL",
								cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
							errors++;
						}
						ircfree(file);
					}
#endif
					ReqConf.authfile = 1;
				}
				else if (!strcmp(cep->ce_varname, "enable"))
					;
				else if (!strcmp(cep->ce_varname, "enable-logging"))
					;
				else if (!strcmp(cep->ce_varname, "use-client-username"))
					;
				else if (!strcmp(cep->ce_varname, "disable-command"))
					;
				else if (!strcmp(cep->ce_varname, "allow-guests"))
#ifndef GUEST
					config_status("command GUEST is not supported, userauth::allow-guests disabled");
#else
					;
#endif
				else if (!strcmp(cep->ce_varname, "message"))
					;
				else if (!strcmp(cep->ce_varname, "require"))
				{
					if (!strcmp(cep->ce_vardata, "password"))
					{
						if (!cep->ce_entries)
						{
							config_error("%s:%i: empty userauth::require block",
								cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
							errors++;
							continue;
						}
						if (!config_find_entry(cep->ce_entries, "mask"))
						{
							config_error("%s:%i: userauth::require without mask item",
								cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
							errors++;
							continue;
						}

						for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
						{
							CHECK_EMPTY(cepp, cep)

							if (!strcmp(cepp->ce_varname, "mask"))
								    ;
							else
							{
								config_error("%s:%i: unknown userauth::require directive %s",
									cepp->ce_fileptr->cf_filename,
									cepp->ce_varlinenum, cepp->ce_varname);
								errors++;
							}
						}
					}
					else
					{
						config_error("%s:%i: unknown block userauth::require %s",
							cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_vardata);
						errors++;
					}
				}
				else
				{
					config_error("%s:%i: unknown directive userauth::%s",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
					errors++;
				}
			}
			*errs = errors;
			return errors ? -1 : 1;
		}
	}
	else if (type == CONFIG_EXCEPT)
	{
		if (!strcmp(ce->ce_vardata, "userauth"))
		{
			if (!config_find_entry(ce->ce_entries, "mask"))
			{
				config_error("%s:%i: except userauth without mask item",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
				errors++;
			}
			else
			{
				for (cep = ce->ce_entries; cep; cep = cep->ce_next)
				{
					CHECK_EMPTY(cep, ce)

					if (!strcmp(cep->ce_varname, "mask"))
						 ;
					else
					{
						config_error("%s:%i: unknown except userauth directive %s",
							cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
						errors++;
						continue;
					}
				}
			}
			*errs = errors;
			return errors ? -1 : 1;
		}
	}

	return 0;
}

static int cb_conf(ConfigFile *cf, ConfigEntry *ce, int type)
{
	ConfigEntry	*cep, *cepp;

	if (type == CONFIG_MAIN)
	{
		if (!strcmp(ce->ce_varname, "userauth"))
		{
			ConfigEntry *file;

			for (cep = ce->ce_entries; cep; cep = cep->ce_next)
			{
				if (!strcmp(cep->ce_varname, "file"))
					;
				else if (!strcmp(cep->ce_varname, "message"))
				{
					ircstrdup(Settings.message, cep->ce_vardata);
				}
				else if (!strcmp(cep->ce_varname, "enable"))
					Settings.enable = config_checkval(cep->ce_vardata, CFG_YESNO);
				else if (!strcmp(cep->ce_varname, "enable-logging"))
					Settings.enable_logging = config_checkval(cep->ce_vardata, CFG_YESNO);
				else if (!strcmp(cep->ce_varname, "use-client-username"))
					Settings.use_client_username = config_checkval(cep->ce_vardata, CFG_YESNO);
				else if (!strcmp(cep->ce_varname, "disable-command"))
					Settings.disable_command = config_checkval(cep->ce_vardata, CFG_YESNO);
				else if (!strcmp(cep->ce_varname, "allow-guests"))
					Settings.allow_guests = config_checkval(cep->ce_vardata, CFG_YESNO);
				else if (!strcmp(cep->ce_varname, "require"))
				{
					if (!strcmp(cep->ce_vardata, "password"))
					{
						for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
							if (!strcmp(cepp->ce_varname, "mask"))
								AddPasswordedHost(cepp->ce_vardata);
					}
				}
			}

			file = config_find_entry(ce->ce_entries, "file");
			ircstrdup(Settings.authfile, file->ce_vardata);
#ifdef USE_LIBCURL
			if (url_is_valid(file->ce_vardata))
				download_authfile(file);
			else
#endif
				read_authfile(Settings.authfile, Settings.authfile);


			return 1;
		}
	}
	else if (type == CONFIG_EXCEPT)
	{
		if (!strcmp(ce->ce_vardata, "userauth"))
		{
			for (cep = ce->ce_entries; cep; cep = cep->ce_next)
				if (!strcmp(cep->ce_varname, "mask"))
					AddAuthException(cep->ce_vardata);

			return 1;
		}
	}

	return 0;
}

static int cb_posttest(int *errs)
{
	int errors = 0;

	if (!ReqConf.authfile)
	{
		config_error("userauth::file missing");
		errors++;
	}

	*errs = errors;
	return errors ? -1 : 1;
}

static void cb_stats(aClient *sptr)
{
	sendto_one(sptr, ":%s %i %s :enable: %d",
		me.name, RPL_TEXT, sptr->name, Settings.enable);
	sendto_one(sptr, ":%s %i %s :enable-logging: %d",
		me.name, RPL_TEXT, sptr->name, Settings.enable_logging);
	sendto_one(sptr, ":%s %i %s :use-client-username: %d",
		me.name, RPL_TEXT, sptr->name, Settings.enable_logging);
	sendto_one(sptr, ":%s %i %s :file: %s",
		me.name, RPL_TEXT, sptr->name, Settings.authfile ? Settings.authfile : "<NULL>");
	sendto_one(sptr, ":%s %i %s :message: %s",
		me.name, RPL_TEXT, sptr->name, Settings.message ? Settings.message : DEF_MESSAGE);
	sendto_one(sptr, ":%s %i %s :disable-command: %d",
		me.name, RPL_TEXT, sptr->name, Settings.disable_command);
#ifdef GUEST
	sendto_one(sptr, ":%s %i %s :allow-guests: %d",
		me.name, RPL_TEXT, sptr->name, Settings.allow_guests);
#endif

	sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'S');
}

static int cb_rehashflag(aClient *cptr, aClient *sptr, char *flag)
{
	int myflag = 0;

	if (!_match(flag, "-all") || (myflag = !_match(flag, "-auth")))
	{
		if (myflag)
			sendto_ops("R%sehashing network staff file on the request of %s",
                                cptr != sptr ? "emotely r" : "", sptr->name);

#ifdef USE_LIBCURL
		if (Download.is_url)
			read_authfile(Download.path, Download.file);
		else
#endif
			read_authfile(Settings.authfile, Settings.authfile);
	}

	return 0;
}

/* ================================================================= */

/*
 * do_client_auth
 *
 *     Warning: GetHost() is not encouraged here to use.
 */

static u_int do_client_auth(aClient *sptr)
{
	AuthLine	*l;
	char		tmp[PASSWDLEN+1], *login, *passwd;
	char		*realhost, *nuip;

	if (SHOWCONNECTINFO)
		sendto_one(sptr, ":%s NOTICE %s :*** Doing authentication...",
			me.name, sptr->name);

	make_hosts(sptr, &realhost, &nuip);

	if (!Find_passworded_userhost(realhost, nuip) || Find_except_userauth(realhost, nuip))
		return 1;

	if (BadPtr(sptr->passwd))
	{
                sendto_snomask(SNO_USERAUTH, "*** Failed authentication by %s!%s@%s -- "
			"no password given",
			sptr->name, sptr->user->username, sptr->user->realhost);
		if (Settings.enable_logging)
			ircd_log(LOG_CLIENT, "Failed authentication by %s!%s@%s -- "
				"no password given",
				sptr->name, sptr->user->username, sptr->user->realhost);
		return 0;
	}

	if (Settings.use_client_username)
	{
		login = sptr->user->username;
		passwd = sptr->passwd;
	}
	else
	{
		strcpy(tmp, sptr->passwd);
		login = strtok(tmp, ":");
		passwd = strtok(NULL, ":");

		if (BadPtr(login) || BadPtr(passwd))
		{
            		sendto_snomask(SNO_USERAUTH, "*** Failed authentication by %s!%s@%s -- "
				"bad syntax for password [given password was: %s]",
				sptr->name, sptr->user->username, sptr->user->realhost,
				sptr->passwd);
			if (Settings.enable_logging)
				ircd_log(LOG_CLIENT, "Failed authentication by %s!%s@%s -- "
					"bad syntax for password [given password was: %s]",
					sptr->name, sptr->user->username, sptr->user->realhost,
					sptr->passwd);
			return 0;
		}
	}

	if (!(l = FindAuthLine(login)))
	{
                sendto_snomask(SNO_USERAUTH, "*** Failed authentication by %s!%s@%s "
			"-- no such username [given password was: %s]",
			sptr->name, sptr->user->username, sptr->user->realhost, sptr->passwd);
		if (Settings.enable_logging)
			ircd_log(LOG_CLIENT, "Failed authentication by %s!%s@%s -- "
				"no such username [given password was: %s]",
				sptr->name, sptr->user->username, sptr->user->realhost,
				sptr->passwd);
		return 0;
	}
	if (Auth_Check(sptr, l->auth, passwd) == -1)
	{
                sendto_snomask(SNO_USERAUTH, "*** Failed authentication by %s!%s@%s -- "
			"password incorrect [given password was: %s]",
			sptr->name, sptr->user->username, sptr->user->realhost, sptr->passwd);
		if (Settings.enable_logging)
			ircd_log(LOG_CLIENT, "Failed authentication by %s!%s@%s -- "
				"password incorrect [given password was: %s]",
				sptr->name, sptr->user->username, sptr->user->realhost,
				sptr->passwd);
		return 0;
	}

	if (sptr->passwd)
	{
		MyFree(sptr->passwd);
		sptr->passwd = NULL;
	}

	if (Settings.enable_logging)
		ircd_log(LOG_CLIENT, "Successful authentication by %s!%s@%s with username %s",
			sptr->name, sptr->user->username, sptr->user->realhost, login);

	return 1;
}

static int cb_pre_connect(aClient *sptr)
{
#ifdef GUEST
	static char *parv[1] = { NULL };
#endif

	if (!do_client_auth(sptr)) /* Authorization failed? */
	{
#ifdef GUEST
		if (Settings.allow_guests && CmdGuest)
		{
			CmdGuest->func(sptr, sptr, 0, parv);
			SetGuest(sptr);
			return 1;
		}
#endif

		return exit_client(sptr, sptr, &me,
			Settings.message ? Settings.message : DEF_MESSAGE);
	}

	return 0;
}

static int m_userauth(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	ConfigItem_except	*e;
	AuthLine		*l;

	if (!IsPerson(sptr))
		return 0;
	if (!MyConnect(sptr) || !IsAnOper(sptr) || Settings.disable_command)
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}
	if (IsNotParam(1))
	{
		sendto_one(sptr, ":%s NOTICE %s :Usage:",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    /userauth <option>",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :Options:",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    lines: displays all the user authentication lines",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    hosts: returns a list of passworded hosts",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    exceptions: shows you the except userauth mask list",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    config: shows the userauth configuration",
			me.name, sptr->name);
		return 0;
	}

	/* Authentication lines */
	if (!strcasecmp(parv[1], "lines"))
	{
		for (l = AuthLines; l; l = l->next)
			sendto_one(sptr, ":%s %i %s :x %s",
				me.name, RPL_TEXT, sptr->name, l->login);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], 'x');
	}

	/* Passworded hosts */
	else if (!strcasecmp(parv[1], "hosts"))
	{
		for (e = PasswordedHosts; e; e = (ConfigItem_except *) e->next)
			sendto_one(sptr, ":%s %i %s :x %s",
				me.name, RPL_TEXT, sptr->name, e->mask);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], 'x');
	}

	/* Exceptions */
	else if (!strcasecmp(parv[1], "exceptions"))
	{
		for (e = AuthExceptions; e; e = (ConfigItem_except *) e->next)
			sendto_one(sptr, ":%s %i %s :x %s",
				me.name, RPL_TEXT, sptr->name, e->mask);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], 'x');
	}

	/* Configuration */
	else if (!strcasecmp(parv[1], "config"))
		cb_stats(sptr);

	/* ? */
	else
	{
		sendto_one(sptr, ":%s NOTICE %s :Unknown option %s."
			" Valid options are: lines | hosts | exceptions | config",
			me.name, sptr->name, parv[1]);
		return 0;
	}

	return 0;
}

#ifdef GUEST
int override_nick(Cmdoverride *ovr, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (!MyConnect(sptr) || !IsPerson(sptr) || IsAnOper(sptr) || !IsGuest(sptr))
		return CallCmdoverride(ovr, cptr, sptr, parc, parv);

	sendto_one(sptr, ERR_GUEST, me.name, sptr->name);
	return 1;
}
#endif
