#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//TODO: on non-mac's, want to include md5.h, not openssl's version...
#include <openssl/md5.h>
//for stat()
#include <sys/types.h>
#include <sys/stat.h>

#include <curl/curl.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#define ROOT "/usr/local/Cache-Static"
#define CACHE_LEVELS 3
//length(ROOT) + "/cache/" + key_len + key_dirseperators + [.deps] + \0
//TODO: this generates a warning - is there a better way?
int MAX_PATH = strlen(ROOT)+7+22+CACHE_LEVELS+5+1;
int MAX_DEPFILE_SIZE = 32767;

//TODO: the below should be read from params in httpd.conf
#define SCACHE_ROOT "/scache"
#define BACKEND "http://localhost:80/mason"

//TODO: check for out of memory conditions after malloc calls!
//TODO: make sure we are free'ing wherever necessary

unsigned static char* base64_16(const unsigned char* from, unsigned char* to);

void warn(char *s) {
	fprintf(stderr, "warning: %s\n", s);
}

void die(char *s) {
	fprintf(stderr, "fatal error: %s\n", s);
	exit(1);
}

struct keyval_pair {
	char *key;
	char *val;
} keyval_pair;

int key_strcmp(struct keyval_pair *a, struct keyval_pair *b) {
	//printf("in key_strcmp: %s(%s) <=> %s(%s)\n", a->key, a->val, b->key, b->val);
	int key_cmp = strcmp(a->key, b->key);
	if(key_cmp!=0) return key_cmp;
	return strcmp(a->val, b->val);
}

unsigned char *make_friendly_key(char *uri, char *query_string) {
	//TODO: make sure to use the same comparison function as perl
	//or perhaps instead of using cmp, define our own in perl?

	if(query_string == NULL) return uri;

	//TODO: allow for "broken" non-keyval pairs, e.g. /cgi/count?1234
	//just count it as a null key or a null val (not sure which)

	int i, g_off, l_off, len, pairs;
	char *p, *t;
	int maxlen_qs=strlen(query_string);
	int maxlen_uri=strlen(uri);
	char *qs_cp = malloc(maxlen_qs*sizeof(char));
	qs_cp = strcpy(qs_cp, query_string);
	char *ret=malloc((maxlen_qs+maxlen_uri)*sizeof(char));
	//TODO: this array should be smaller
	struct keyval_pair keyvals[maxlen_qs/2];

	i=0;
	while(*qs_cp != '\0') {
		p = index(qs_cp, '=');
		if(p != NULL) {
			keyvals[i].key = malloc((p-qs_cp+1)*sizeof(char));
			strncpy(keyvals[i].key, qs_cp, (p-qs_cp));
			keyvals[i].key[p-qs_cp] = '\0';
			//printf("key: %s\n", keyvals[i].key);
		} else {
			die("can't find expected char '=' in query string!");
		}
		qs_cp = p+1; //skip the '&'
		p = index(qs_cp, '&');
		if(p != NULL) {
			keyvals[i].val = malloc((p-qs_cp+1)*sizeof(char));
			strncpy(keyvals[i].val, qs_cp, (p-qs_cp));
			keyvals[i].val[p-qs_cp] = '\0';
			//printf("val1: %s\n", keyvals[i].val);
			qs_cp = p+1; //skip the '&'
		} else {
			p = index(qs_cp, '\0');
			keyvals[i].val = malloc((p-qs_cp+1)*sizeof(char));
			strncpy(keyvals[i].val, qs_cp, (p-qs_cp));
			keyvals[i].val[p-qs_cp] = '\0';
			//printf("val2: %s\n", keyvals[i].val);
			qs_cp = p;
		}
		i++;
	}
	pairs=i;

	qsort(keyvals, pairs, sizeof(struct keyval_pair), (void *)key_strcmp);

	//keyvals -> ret
	for(g_off=0; g_off<maxlen_uri; g_off++) {
		ret[g_off] = uri[g_off];
	}
	ret[g_off++] = '?';

	for(i=0; i<pairs; i++) {
		t=keyvals[i].key;
		len=strlen(t);
		for(l_off=0; l_off<len; g_off++, l_off++) {
			ret[g_off] = t[l_off];
		}
		ret[g_off++] = '=';
		t=keyvals[i].val;
		len=strlen(t);		
		for(l_off=0; l_off<len; g_off++, l_off++) {
			ret[g_off] = t[l_off];
		}
		if(g_off < (maxlen_qs+maxlen_uri)) { ret[g_off++] = '&'; }
	}
	for(i=0; i<pairs; i++) {
		free(keyvals[i].key);
		free(keyvals[i].val);
	}
	ret[g_off]='\0';

	//printf("%s\n", ret);

	return (unsigned char *)ret;
}

unsigned char *make_key_from_friendly(unsigned char *fkey) {
	unsigned char *buf  = malloc(16*sizeof(unsigned char));
	unsigned char *buf2 = malloc(23*sizeof(unsigned char));
	char          *buf3 = malloc(46*sizeof(char));
	char *t;
	int i;

	MD5(fkey, strlen((char *)fkey), buf);
	base64_16(buf, buf2);
	free(buf);

	//use our path convention
	t=buf3;
	for(i=0; i<CACHE_LEVELS; i++) {
		sprintf(t, "%c/", buf2[i]);
		t+=2;
	}
	sprintf(t, "%s\0", &buf2[i]);
	free(buf2);

	return (unsigned char *)buf3;
}

time_t get_mtime(char *fn) {
	struct stat st;
	if (stat(fn, &st)==-1) return ((time_t)-1);
	return st.st_atimespec.tv_sec;
}

char *get_if_same(char *key) {
	FILE *f;
	int sz = 0;
	//TODO: abstract the stuff for reading ret -> mem to a function
	// (use it for s and buf as well?)
	char buf[MAX_DEPFILE_SIZE+1];
	char s[MAX_DEPFILE_SIZE+1];
	char dfn[MAX_PATH];
	char fn[MAX_PATH];
	char *ret;
	char *t, *t2;
	time_t gen_time, time;
	fn[0]='\0';
	dfn[0]='\0';

	//set up file names
	strcat(dfn, ROOT);
	strcat(dfn, "/cache/");
	strcat(dfn, key);
	strcpy(fn, dfn);
	strcat(dfn, ".deps");

	printf("dfn: %s\n", dfn);
	printf("fn: %s\n", fn);

	//load deps
	f = fopen(dfn, "r");
	if(f == NULL) {
		fprintf(stderr, "can't open dep file: %s\n", dfn);
		return NULL;
	}
	fread(buf, sizeof(char), MAX_DEPFILE_SIZE, f);
	if(!feof(f)) { warn("dep file is too big!"); return NULL; }
	if(ferror(f)) { warn("error reading dep file!"); return NULL; }
	fclose(f);

	//first, stat the cache file
	gen_time = get_mtime(fn);
	if(gen_time < 0) {
		fprintf(stderr, "can't find cached file %s, creating\n", fn);
		return NULL;
	}
	printf("%s last modified at %d\n", fn, gen_time);

	t=buf;
	while(t != NULL) {
		t2=t;
		t = index(t, '\n');
		if(t != NULL) {
			strncpy(s, t2, (t-t2)*sizeof(char));
			//determine if key is changed or not
			time = get_mtime(s);
			printf("key: %s, time: %d\n", s, time);
			if(time < 0) {
				fprintf(stderr, "can't open dep file: %s", s);
				return NULL;
			}
			if(time > gen_time) {
				fprintf(stderr, "dependency %s has changed, regenerating...", s);
				return NULL;
			}
			t++;
		}
	}

	//open the file
	f = fopen(fn, "r");
	if(f == NULL) {
		fprintf(stderr, "can't open cache file: %s\n", fn);
		return NULL;
	}

	//find file size
	if(fseek(f, 0L, SEEK_END)<0) { //go to the end
		fprintf(stderr, "can't fseek to end on cache file: %s\n", fn);
		return NULL;
	}
	sz = ftell(f);   //get current position
	if(sz<0) {
		fprintf(stderr, "can't ftell on cache file: %s\n", fn);
		return NULL;
	}
	if(fseek(f, 0L, SEEK_SET)<0) { //go back to the begining
		fprintf(stderr, "can't fseek to beginning on cache file: %s\n", fn);
		return NULL;
	}

	//allocate enough space for the return buffer
	ret = malloc((sz)*sizeof(char));
	if(ret==NULL) {
		fprintf(stderr, "can't malloc for cache file: %s\n", fn);
		return NULL;
	}

	fread(ret, sizeof(char), sz, f);
	if(ferror(f)) { warn("error reading cache file!"); return NULL; }
	fclose(f);

	//terminate the string	
	ret[sz] = '\0';

	return ret;
}

size_t writer(void *ptr, size_t size, size_t nmemb, void *vr) {
	request_rec *r = (request_rec *)vr;
	char buf[CURL_MAX_WRITE_SIZE];
	//memcpy to add zero termination
	memcpy(buf, ptr, size*nmemb);
	buf[size*nmemb] = '\0';
	ap_rputs(buf, r);
	return size * nmemb;
}

void geturi(char *base, char *uri, request_rec *r) {
	char *full_url = malloc(strlen(base)+strlen(uri));
	strcpy(full_url, base);
	strcat(full_url, uri);

	CURL *ctx = curl_easy_init();
	curl_easy_setopt(ctx, CURLOPT_NOPROGRESS, 1);
	curl_easy_setopt(ctx, CURLOPT_URL, full_url);
	curl_easy_setopt(ctx, CURLOPT_WRITEFUNCTION, writer);
	curl_easy_setopt(ctx, CURLOPT_WRITEDATA, (void *)r);
	curl_easy_perform(ctx);
	curl_easy_cleanup(ctx);
}

unsigned static char* base64_16(const unsigned char* from, unsigned char* to) {
	static char* base64 =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const unsigned char *end = from + 16;
	unsigned char c1, c2, c3;
	unsigned char *d = to;

	while (1) {
		c1 = *from++;
		*d++ = base64[c1>>2];
		if (from == end) {
			*d++ = base64[(c1 & 0x3) << 4];
			break;
		}
		c2 = *from++;
		c3 = *from++;
		*d++ = base64[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)];
		*d++ = base64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
		*d++ = base64[c3 & 0x3F];
	}
	*d = '\0';
	return to;
}

/* the content handler */
static int scache_handler(request_rec *r) {
	char *uri, *fkey, *key, *ret;

	r->content_type = "text/html";
	ap_send_http_header(r);

	uri = r->uri;
	//sanity check - make sure they're requesting something in our root
	if(strncmp(uri, SCACHE_ROOT, strlen(SCACHE_ROOT)) != 0) {
		ap_rprintf(r, "uri(%s) != SCACHE_ROOT(%s)<br />\n", uri, SCACHE_ROOT);
		//TODO: warn & return !OK here
	} else {
		ap_rprintf(r, "uri(%s) passed sanity check<br />\n", uri);
	}
	uri+=strlen(SCACHE_ROOT);

	ap_rprintf(r, "request: %s?%s<br />\n", uri, r->args);
	fkey = make_friendly_key(uri, r->args);
	ap_rprintf(r, "friendly key: %s<br />\n", fkey);
	key = make_key_from_friendly(fkey);
	ap_rprintf(r, "key: %s<br />\n", key);
	ret = get_if_same(key);
	if(ret == NULL) {
		fprintf(stderr, "mod_scache: going to source for %s (%s)\n", fkey, key);
		geturi(BACKEND, uri, r);
	} else {
		fprintf(stderr, "mod_scache: using cached data for %s (%s)\n", fkey, key);
		ap_rprintf(r, "response: %s", ret);
	}

	return OK;
}

/* Make the name of the content handler known to Apache */
static handler_rec scache_handlers[] = {
	{"scache-handler", scache_handler},
	{NULL}
};

module MODULE_VAR_EXPORT scache_module = {
	STANDARD_MODULE_STUFF,
	NULL,               /* module initializer                 */
	NULL,               /* per-directory config creator       */
	NULL,               /* dir config merger                  */
	NULL,               /* server config creator              */
	NULL,               /* server config merger               */
	NULL,               /* command table                      */
	scache_handlers,    /* [7]  content handlers              */
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

