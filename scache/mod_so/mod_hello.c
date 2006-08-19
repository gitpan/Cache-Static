#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_main.h"
#include "util_script.h"
#include "util_md5.h"
 
module MODULE_VAR_EXPORT hello_module;

#define BANNER_PGM "/usr/bin/banner"

typedef struct {
    char *to;
    char *banner;
} hello_dir_config;

static void *hello_create_dir_config(pool *p, char *path)
{
    hello_dir_config *cfg = 
	(hello_dir_config *)ap_pcalloc(p, sizeof(hello_dir_config));
    cfg->to = "world";
    cfg->banner = BANNER_PGM;
    return (void *)cfg;
}

static void *hello_merge_dir_config (pool *p, void *basev, void *addv)
{
    hello_dir_config *new = 
	(hello_dir_config *)ap_pcalloc (p, sizeof(hello_dir_config));
    hello_dir_config *base = (hello_dir_config *)basev;
    hello_dir_config *add = (hello_dir_config *)addv;
    
    new->banner = add->banner ?
	add->banner : base->banner;

    new->to = add->to ?
	add->to : base->to;

    return (void*)new; 
}

static const char *hello_cmd_to(cmd_parms *parms, void *mconfig,
				char *to) 
{
    hello_dir_config *cfg = (hello_dir_config *)mconfig;
    cfg->to = (char *)ap_pstrdup(parms->pool, to);
    return NULL;
}

static const char *hello_cmd_banner(cmd_parms *parms, void *mconfig,
				char *pgm) 
{
    hello_dir_config *cfg = (hello_dir_config *)mconfig;
    cfg->banner = (char *)ap_pstrdup(parms->pool, pgm);
    return NULL;
}

static command_rec hello_cmds[] =
{
    {
	"HelloTo",              /* directive name */
	hello_cmd_to,            /* config action routine */
	NULL,                   /* argument to include in call */
	OR_ALL,             /* where available */
	TAKE1,                /* arguments */
	"Who we say hello to, default is `World'"
                                /* directive description */
    },
    {
	"HelloBanner",              /* directive name */
	hello_cmd_banner,            /* config action routine */
	NULL,                   /* argument to include in call */
	OR_ALL,             /* where available */
	TAKE1,                /* arguments */
	"banner program path"
                                /* directive description */
    },
    {NULL}
};

/* here's the content handler */
static int hello_handler(request_rec *r) {
    hello_dir_config *cfg = 
	ap_get_module_config(r->per_dir_config, &hello_module);     
   const char* hostname;
 
   r->content_type = "text/html";
   ap_send_http_header(r);
   hostname = ap_get_remote_host(r->connection, 
				 r->per_dir_config, REMOTE_NAME);
 
   ap_rputs("<HTML>\n", r);
   ap_rputs("<HEADER>\n", r);
   ap_rputs("<TITLE>Hello There</TITLE>\n", r);
   ap_rputs("</HEADER>\n", r);
   ap_rputs("<BODY>\n", r);
   ap_rprintf(r, "<H1>Hello %s</H1>\n", hostname);
   ap_rputs("Who would take this book seriously if the first example didn't\n",r);
   ap_rprintf(r, "say \"hello %s\"?\n", cfg->to);

   ap_rputs("</BODY>\n", r);
   ap_rputs("</HTML>\n", r);

   return OK;
}
 
/* start "port" of tryit.cgi */
static int util_read(request_rec *r, const char **rbuf)
{
    int rc = OK;

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
	return rc;
    }

    if (ap_should_client_block(r)) {
	char argsbuffer[HUGE_STRING_LEN];
	int rsize, len_read, rpos=0;
	long length = r->remaining;
	*rbuf = ap_pcalloc(r->pool, length + 1); 

	ap_hard_timeout("util_read", r);

	while ((len_read =
		ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
	    ap_reset_timeout(r);
	    if ((rpos + len_read) > length) {
		rsize = length - rpos;
	    }
	    else {
		rsize = len_read;
	    }
	    memcpy((char*)*rbuf + rpos, argsbuffer, rsize);
	    rpos += rsize;
	}

	ap_kill_timeout(r);
    }

    return rc;
}

#define DEFAULT_ENCTYPE "application/x-www-form-urlencoded"

static int read_post(request_rec *r, table **tab)
{
    const char *data;
    const char *key, *val, *type;
    int rc = OK;

    if(r->method_number != M_POST) {
	return rc;
    }

    type = ap_table_get(r->headers_in, "Content-Type");
    if(strcasecmp(type, DEFAULT_ENCTYPE) != 0) {
	return DECLINED;
    }

    if((rc = util_read(r, &data)) != OK) {
	return rc;
    }

    if(*tab) {
	ap_clear_table(*tab);
    }
    else {
	*tab = ap_make_table(r->pool, 8);
    }

    while(*data && (val = ap_getword(r->pool, &data, '&'))) {
	key = ap_getword(r->pool, &val, '=');

	ap_unescape_url((char*)key);
	ap_unescape_url((char*)val);

	ap_table_merge(*tab, key, val);
    }

    return OK;
}

static void hello_util_start_html(request_rec *r, char *title)
{
   ap_rputs("<HTML>\n                           ",r);
   ap_rputs("<HEADER>\n                         ",r);
   ap_rprintf(r, "<TITLE>%s</TITLE>\n       ",title);
   ap_rputs("</HEADER>\n                        ",r);
   ap_rputs("<BODY>\n                           ",r);
}

static void hello_util_end_html(request_rec *r)
{
    ap_rputs("</BODY></HTML>\n", r);
}

static void hello_util_start_form(request_rec *r, char *type)
{
    ap_rprintf(r, "<FORM METHOD=\"POST\"  ENCTYPE=\"%s\">\n",
	       type ? type : DEFAULT_ENCTYPE);
}

static void hello_util_end_form(request_rec *r)
{
    ap_rputs("</FORM>\n", r);
}

static void hello_util_submit(request_rec *r, char *name)
{
    ap_rprintf(r, "<INPUT TYPE=\"submit\" NAME=\"%s\">\n", 
	       name ? name : ".submit");
}

static void hello_util_textfield(request_rec *r, char *key, char *val)
{
    ap_rprintf(r, "<INPUT TYPE=\"text\" NAME=\"%s\" VALUE=\"%s\">\n", key, val);
}

static int hello_util_isa_default(char *wanted, char **list)
{
    int i;
    for(i=0; list[i]; i++) {
	if(!strcmp(wanted, list[i]))
	    return 1;
    }
    return 0;
}

static void hello_util_checkbox_group(request_rec *r, char *name, char **values, char **defaults)
{
    int i;
    for (i=0; values[i]; i++) {
	ap_rprintf(r, 
		   "<INPUT TYPE=\"checkbox\" NAME=\"%s\" VALUE=\"%s\" %s>%s\n",
		   name, values[i], 
		   hello_util_isa_default(values[i], defaults) ?
		   "CHECKED" : "", values[i]);
    }
}

static void hello_util_popup_menu(request_rec *r, char *name, char **values)
{
    int i;
    ap_rprintf(r, "<SELECT NAME=\"%s\">\n", name); 
    for (i=0; values[i]; i++) 
	ap_rprintf(r, "<OPTION  VALUE=\"%s\">%s\n", values[i], values[i]); 
    ap_rputs("</SELECT>\n", r);
}

#define P_SEP ap_rputs("<P>", r)

static char *checkbox_combo[] = {
    "eenie","meenie","minie","moe",NULL
};

static char *checkbox_combo_defaults[] = {
    "eenie","minie",NULL 
};

static char *popup_menu_colors[] = {
    "red","green","blue","chartreuse",NULL
};

/*
 * <Location /hello-form> 
 * SetHandler hello-form-handler 
 * </Location> 
 */
static int hello_form_handler(request_rec *r) {
    table *post = NULL;
    int rc = OK;

    if((rc = read_post(r, &post)) != OK)
	return rc;

    r->content_type = "text/html";
    ap_send_http_header(r);

    hello_util_start_html(r, "Hello");
    hello_util_start_form(r, NULL);
    ap_rputs("What's your name? ", r);
    hello_util_textfield(r, "name", "");
    P_SEP;
    ap_rputs("What's the combination?", r);
    P_SEP;
    hello_util_checkbox_group(r, "words", 
			      checkbox_combo, checkbox_combo_defaults);
    P_SEP;
    ap_rputs("What's your favorite color? ", r);
    hello_util_popup_menu(r, "color", popup_menu_colors);
    P_SEP;
    hello_util_submit(r, NULL);
    hello_util_end_form(r);
    P_SEP;

    if(post && !ap_is_empty_table(post)) {
        ap_rprintf(r, "Your name is: %s", ap_table_get(post, "name")); 
        P_SEP;
        ap_rprintf(r, "The keywords are: %s", ap_table_get(post, "words"));
	P_SEP;
        ap_rprintf(r, "Your favorite color is: %s", ap_table_get(post, "color"));
   }

   hello_util_end_html(r);
   return OK;
}
/* end "port" of tryit.cgi */

static int banner_child(void *rp, child_info *pinfo)
{
    char **env;
    int child_pid;
    request_rec *r = (request_rec *)rp;
    hello_dir_config *cfg = 
	ap_get_module_config(r->per_dir_config, &hello_module);     

    env = ap_create_environment(r->pool, r->subprocess_env);
    ap_error_log2stderr(r->server);

    r->filename = cfg->banner ? cfg->banner : BANNER_PGM;
    r->args = "-w40+Goodbye%20World";

    ap_cleanup_for_exec();
    child_pid = ap_call_exec(r, pinfo, r->filename, env, 0);
#ifdef WIN32
    return(child_pid);
#else
    ap_log_error(APLOG_MARK, APLOG_ERR, NULL, "exec of %s failed", r->filename);
    exit(0);
    /*NOTREACHED*/
    return(0);
#endif
}

static int hello_banner_handler(request_rec *r)
{
    BUFF *pipe_input;
    hello_dir_config *cfg = 
	(hello_dir_config *)ap_pcalloc(r->pool, sizeof(hello_dir_config));

    if (!ap_bspawn_child(r->pool, banner_child,
			 (void *)r, kill_after_timeout,
			 NULL, &pipe_input, NULL)) {
	ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
		     "couldn't spawn child process: %s", cfg->banner);
	return SERVER_ERROR;
    }

    r->content_type = "text/plain";
    ap_send_http_header(r);
    ap_send_fb(pipe_input, r);
    ap_bclose(pipe_input);
    return OK;
}

static int errlog_header(void *arg, const char *k, const char *v)
{
    FILE *fp = (FILE*)arg;
    fprintf(fp, "%s: %s\n", k, v);
    return 1;
}

void request_as_string(request_rec *r)
{
    FILE *fp = r->server->error_log;
    if(!fp) return;
    if(r->server->loglevel < (APLOG_DEBUG & APLOG_LEVELMASK))
	return;

    fprintf(fp, "%s\n", r->the_request);

    ap_table_do(errlog_header, (void*)fp, r->headers_in, NULL);
    fprintf(fp, "\n%s %s\n", r->protocol, r->status_line);

    ap_table_do(errlog_header, (void*)fp, r->headers_out, NULL);
    ap_table_do(errlog_header, (void*)fp, r->err_headers_out, NULL);
    fprintf(fp, "\n");
}

table *util_parse_cookie(request_rec *r)
{
    const char *data = ap_table_get(r->headers_in, "Cookie");
    table *cookies;
    const char *pair;
    if(!data) return NULL;

    cookies = ap_make_table(r->pool, 4);
    while(*data && (pair = ap_getword(r->pool, &data, ';'))) {
	const char *key, *value;
	if(*data == ' ') ++data;
	key = ap_getword(r->pool, &pair, '=');
	while(*pair && (value = ap_getword(r->pool, &pair, '&'))) {
	    ap_unescape_url((char *)value);
	    ap_table_add(cookies, key, value);
	}
    }

    return cookies;
}

/* Make the name of the content handler known to Apache */
static handler_rec hello_handlers[] =
{
    {"hello-handler", hello_handler},
    {"hello-form-handler", hello_form_handler},
    {"hello-banner-handler", hello_banner_handler},
    {NULL}
};

/* Tell Apache what phases of the transaction we handle */
module MODULE_VAR_EXPORT hello_module =
{
    STANDARD_MODULE_STUFF,
    NULL,               /* module initializer                 */
    hello_create_dir_config,  /* per-directory config creator       */
    hello_merge_dir_config,   /* dir config merger                  */
    NULL,               /* server config creator              */
    NULL,               /* server config merger               */
    hello_cmds,         /* command table                      */
    hello_handlers,     /* [7]  content handlers              */
    NULL,               /* [2]  URI-to-filename translation   */
    NULL,               /* [5]  check/validate user_id        */
    NULL,               /* [6]  check user_id is valid *here* */
    NULL,               /* [4]  check access by host address  */
    NULL,               /* [7]  MIME type checker/setter      */
    NULL,               /* [8]  fixups                        */
    NULL,               /* [9]  logger                        */
    NULL,               /* [3]  header parser                 */
    NULL,               /* process initialization             */
    NULL,               /* process exit/cleanup               */
    NULL                /* [1]  post read_request handling    */
};
