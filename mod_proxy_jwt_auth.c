/*
**  mod_proxy_jwt_auth: Remap request ENV vars and pass to proxied app as a
**  JSON Web Token via a Authorization Bearer header.
**
**  See README.md for details and LICENSE for licensing information.
*/

#include "apr.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "jwt.h"

APLOG_USE_MODULE(proxy_jwt_auth);

typedef struct {
  int enabled:1;
  int allow_missing:1;
  apr_table_t *claim_map;
  jwt_alg_t token_alg;
  unsigned char *token_alg_key;
  int token_alg_key_len;
  int token_duration;
  const char *header_name;
} proxy_jwt_auth_config_values;

typedef struct {
  unsigned int enabled:1;
  unsigned int allow_missing:1;
  // No claim_map: Additive, and apr_is_empty_table can be used instead
  unsigned int token_alg:1;
  unsigned int token_alg_key:1;
  // No token_alg_key_len: Always set with token_alg_key
  unsigned int token_duration:1;
  unsigned int header_name:1;
} proxy_jwt_auth_config_flags;

typedef struct {
  proxy_jwt_auth_config_values *values;
  proxy_jwt_auth_config_flags *isset;
} proxy_jwt_auth_config;

typedef enum {
  dir_enabled,
  dir_allow_missing,
  dir_claim_map,
  dir_token_alg,
  dir_token_alg_key,
  dir_token_duration,
  dir_header_name
} proxy_jwt_auth_directive_enum;

// The following struct is for passing multiple variables into the claim_map apr_table_do iterator
typedef struct {
  proxy_jwt_auth_config *conf;
  request_rec *r; /* Apache request struct */
  jwt_t *token;   /* JWT token to add claims to */
  int error;      /* Error flag: will be set to !0 when something is wrong */
} iterate_claim_map_data;

/****************************** Function Prototypes ******************************/
void load_key_file(apr_pool_t *pool, const char *path, proxy_jwt_auth_config *conf);
jwt_alg_t str_to_jwt_alg(apr_pool_t *pool, const char *alg);

void *allocate_config(apr_pool_t *pool);
void *create_dir_conf(apr_pool_t *pool, char *context);
void *create_server_conf(apr_pool_t *pool, server_rec *s);
void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD);

static const char *set_config_single_arg(cmd_parms * cmd, void* config, const char* value);
static const char *set_config_double_arg(cmd_parms *cmd, void *config, const char *value1, const char *value2);

int print_request_env_keys(void* rec_v, const char *key, const char *value);
int iterate_claim_map(void* data_v, const char *env_key, const char *jwt_key);
int map_env_claims(request_rec *r, proxy_jwt_auth_config *conf, jwt_t *token);
int add_auth_header(request_rec *r, proxy_jwt_auth_config *conf);

static int proxy_jwt_auth_handler(request_rec *r);
static void proxy_jwt_auth_register_hooks(apr_pool_t *p);

/****************************** Apache Module API Directives ******************************/
static const command_rec proxy_jwt_auth_directives[] = {
  AP_INIT_TAKE1("ProxyJwtAuthEnabled",               set_config_single_arg, (void *)dir_enabled,        OR_ALL, "Enable or disable mod_proxy_jwt_auth"),
  AP_INIT_TAKE1("ProxyJwtAuthAllowMissing",          set_config_single_arg, (void *)dir_allow_missing,  OR_ALL, "Enable missing env var tolerance"),
  AP_INIT_TAKE2("ProxyJwtAuthClaimMap",              set_config_double_arg, (void *)dir_claim_map,      OR_ALL, "Add a request env var ID to JWT claim ID map"),
  AP_INIT_TAKE1("ProxyJwtAuthTokenAlgorithm",        set_config_single_arg, (void *)dir_token_alg,      OR_ALL, "Set JWT token algorithm"),
  AP_INIT_TAKE1("ProxyJwtAuthTokenAlgorithmKeyPath", set_config_single_arg, (void *)dir_token_alg_key,  OR_ALL, "File path to the JWT token algorithm key file"),
  AP_INIT_TAKE1("ProxyJwtAuthTokenDuration",         set_config_single_arg, (void *)dir_token_duration, OR_ALL, "JWT token duration in seconds"),
  AP_INIT_TAKE1("ProxyJwtAuthHeaderName",            set_config_single_arg, (void *)dir_header_name,    OR_ALL, "Set HTTP Header name"),
  { NULL }
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA proxy_jwt_auth_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_conf,                /* create per-dir    config structures */
    merge_conf,                     /* merge  per-dir    config structures */
    create_server_conf,             /* create per-server config structures */
    merge_conf,                     /* merge  per-server config structures */
    proxy_jwt_auth_directives,     /* table of config file commands       */
    proxy_jwt_auth_register_hooks  /* register hooks                      */
};

/****************************** Functions ******************************/
/********** Configuration Helpers **********/
void load_key_file(apr_pool_t *pool, const char *path, proxy_jwt_auth_config *conf) {
  // Not using apr_file methods as apr_file_read_full was returning "Bad Address" which is just confusing.
  FILE *fp;
  int bytes_read;

  fp = fopen(path, "r");
  if(fp == NULL) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, APLOGNO(99900) "mod_proxy_jwt_auth: Unable to open key file %s: %s", path, strerror(errno));
    abort();
  }

  // Seek to the end and get the length
  fseek(fp, 0, SEEK_END);
  conf->values->token_alg_key_len = ftell(fp);
  rewind(fp);

  conf->values->token_alg_key = apr_pcalloc(pool, conf->values->token_alg_key_len);
  bytes_read = fread(conf->values->token_alg_key, 1, conf->values->token_alg_key_len, fp);
  fclose(fp);

  if(bytes_read != conf->values->token_alg_key_len) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, APLOGNO(99901) "mod_proxy_jwt_auth: Error while reading key file %s: read %d/%d bytes", path, bytes_read, conf->values->token_alg_key_len);
    abort();
  }

  *(conf->values->token_alg_key + conf->values->token_alg_key_len) = '\0';
  conf->isset->token_alg_key = 1;
}

jwt_alg_t str_to_jwt_alg(apr_pool_t *pool, const char *alg) {
  // This is basically a copy of jwt_str_alg from libjwt which isn't available in this scope for some reason
  if (!strcasecmp(alg, "none"))
    return JWT_ALG_NONE;
  else if (!strcasecmp(alg, "HS256"))
    return JWT_ALG_HS256;
  else if (!strcasecmp(alg, "HS384"))
    return JWT_ALG_HS384;
  else if (!strcasecmp(alg, "HS512"))
    return JWT_ALG_HS512;
  else if (!strcasecmp(alg, "RS256"))
    return JWT_ALG_RS256;
  else if (!strcasecmp(alg, "RS384"))
    return JWT_ALG_RS384;
  else if (!strcasecmp(alg, "RS512"))
    return JWT_ALG_RS512;
  else if (!strcasecmp(alg, "ES256"))
    return JWT_ALG_ES256;
  else if (!strcasecmp(alg, "ES384"))
    return JWT_ALG_ES384;
  else if (!strcasecmp(alg, "ES512"))
    return JWT_ALG_ES512;

  ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, APLOGNO(99902) "mod_proxy_jwt_auth: Invalid JWT algorithm: %s", alg);
  abort();
}

/********** Configuration Functions **********/
void *allocate_config(apr_pool_t *pool) {
  proxy_jwt_auth_config *conf = apr_pcalloc(pool, sizeof(proxy_jwt_auth_config));
  conf->values = apr_pcalloc(pool, sizeof(proxy_jwt_auth_config_values));
  if(conf->values == NULL)
    return NULL;
  conf->isset = apr_pcalloc(pool, sizeof(proxy_jwt_auth_config_flags));
  if(conf->isset == NULL)
    return NULL;
  return conf;
}

void *create_dir_conf(apr_pool_t *pool, char *context) {
  proxy_jwt_auth_config *conf = allocate_config(pool);
  if(conf) {
    conf->values->enabled = 0;
    conf->values->allow_missing = 0;
    conf->values->claim_map = apr_table_make(pool, 0);
    conf->values->token_alg = JWT_ALG_NONE;
    conf->values->token_alg_key = NULL;
    conf->values->token_alg_key_len = 0;
    conf->values->token_duration = 30;
    conf->values->header_name = "Authorization";
  }
  return conf;
}

void *create_server_conf(apr_pool_t *pool, server_rec *s) {
  return create_dir_conf(pool, "server");
}

void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD) {
  proxy_jwt_auth_config *base = (proxy_jwt_auth_config *) BASE ; /* This is what was set in the parent context */
  proxy_jwt_auth_config *add  = (proxy_jwt_auth_config *) ADD ;   /* This is what is set in the new context */
  proxy_jwt_auth_config *conf = allocate_config(pool);

  /* Merge configurations */
  conf->values->enabled = ( add->isset->enabled == 0 ) ? base->values->enabled : add->values->enabled;
  conf->isset->enabled = add->isset->enabled | base->isset->enabled;

  conf->values->allow_missing = ( add->isset->allow_missing == 0 ) ? base->values->allow_missing : add->values->allow_missing;
  conf->isset->allow_missing = add->isset->allow_missing | base->isset->allow_missing;

  conf->values->claim_map = apr_table_clone(pool, base->values->claim_map);
  apr_table_overlap(conf->values->claim_map, add->values->claim_map, APR_OVERLAP_TABLES_SET);

  conf->values->token_alg = (add->isset->token_alg == 0) ? base->values->token_alg : add->values->token_alg;
  conf->isset->token_alg = add->isset->token_alg | base->isset->token_alg;

  if (add->isset->token_alg_key == 0) {
    conf->values->token_alg_key = base->values->token_alg_key;
    conf->values->token_alg_key_len = base->values->token_alg_key_len;
  } else {
    conf->values->token_alg_key = add->values->token_alg_key;
    conf->values->token_alg_key_len = add->values->token_alg_key_len;
  }
  conf->isset->token_alg_key = add->isset->token_alg_key | base->isset->token_alg_key;

  conf->values->token_duration = ( add->isset->token_duration == 0 ) ? base->values->token_duration : add->values->token_duration;
  conf->isset->token_duration = add->isset->token_duration | base->isset->token_duration;

  conf->values->header_name = ( add->isset->header_name == 0 ) ? base->values->header_name : add->values->header_name;
  conf->isset->header_name = add->isset->header_name | base->isset->header_name;

  return conf ;
}

static const char *set_config_single_arg(cmd_parms *cmd, void *config, const char *value) {
  proxy_jwt_auth_config *conf;

  if(!cmd->path) {
    conf = (proxy_jwt_auth_config *) ap_get_module_config(cmd->server->module_config, &proxy_jwt_auth_module);
  } else {
    conf = (proxy_jwt_auth_config *) config;
  }

  switch ((proxy_jwt_auth_directive_enum)cmd->info) {
  case dir_enabled:
    if (!strcasecmp(value, "on")) {
      conf->values->enabled = 1;
      conf->isset->enabled = 1;
    }
    else {
      conf->values->enabled = 0;
      conf->isset->enabled = 1;
    }
    break;
  case dir_allow_missing:
    if (!strcasecmp(value, "on")) {
      conf->values->allow_missing = 1;
      conf->isset->allow_missing = 1;
    }
    else {
      conf->values->allow_missing = 0;
      conf->isset->allow_missing = 1;
    }
    break;
  case dir_token_alg:
    conf->values->token_alg = str_to_jwt_alg(cmd->pool, value);
    conf->isset->token_alg = 1;
    break;
  case dir_token_alg_key:
    load_key_file(cmd->pool, value, conf);
    break;
  case dir_token_duration:
    conf->values->token_duration = atoi(value);
    conf->isset->token_duration = 1;
    ap_log_perror(APLOG_MARK, APLOG_INFO, 0, cmd->pool, APLOGNO(99903) "mod_proxy_jwt_auth: Token duration set to %d seconds", conf->values->token_duration);
    break;
  case dir_header_name:
    conf->values->header_name = value;
    conf->isset->header_name = 1;
    break;
  default:
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool, APLOGNO(99904) "mod_proxy_jwt_auth: INTERNAL ERROR: Unknown directive 0x%02x passed to set_config_single_arg", (proxy_jwt_auth_directive_enum)cmd->info);
    abort();
  }

  return NULL;
}

static const char *set_config_double_arg(cmd_parms *cmd, void *config, const char *value1, const char *value2) {
  proxy_jwt_auth_config *conf;

  if(!cmd->path) {
    conf = (proxy_jwt_auth_config *) ap_get_module_config(cmd->server->module_config, &proxy_jwt_auth_module);
  } else {
    conf = (proxy_jwt_auth_config *) config;
  }

  switch ((proxy_jwt_auth_directive_enum)cmd->info) {
  case dir_claim_map:
    apr_table_set(conf->values->claim_map, value1, value2);
    break;
  default:
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool, APLOGNO(99905) "mod_proxy_jwt_auth: INTERNAL ERROR: Unknown directive 0x%02x passed to set_config_double_arg", (proxy_jwt_auth_directive_enum)cmd->info);
    abort();
  }

  return NULL;
}

/********** Handler Helpers **********/
int print_request_env_keys(void* rec_v, const char *key, const char *value) {
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, (request_rec *)(rec_v), APLOGNO(99906) "mod_proxy_jwt_auth: Available key: %s", key);
  return 1;
}


int iterate_claim_map(void* data_v, const char *env_key, const char *jwt_key) {
  iterate_claim_map_data *data = (iterate_claim_map_data *)(data_v);
  const char *env_value;

  env_value = apr_table_get(data->r->subprocess_env, env_key);
  if (env_value == NULL) {
    if (data->conf->values->allow_missing == 0) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, data->r, APLOGNO(99907) "mod_proxy_jwt_auth: Request env missing required key %s", env_key);
      apr_table_do(print_request_env_keys, data->r, data->r->subprocess_env, NULL);
      data->error = 1;
      return 0;
    }

    // Missing data is tolerated, but jwt_add_grant fails on null pointers.  Set the value to an empty string.
    env_value = "";
  }

  if (jwt_add_grant(data->token, jwt_key, env_value) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, data->r, APLOGNO(99908) "mod_proxy_jwt_auth: Failed to add claim %s to the token", jwt_key);
    data->error = 1;
    return 0;
  }

  return 1;
}

int map_env_claims(request_rec *r, proxy_jwt_auth_config *conf, jwt_t *token) {
  iterate_claim_map_data *iterator_data = apr_pcalloc(r->pool, sizeof(iterate_claim_map_data));

  iterator_data->r = r;
  iterator_data->conf = conf;
  iterator_data->token = token;
  iterator_data->error = 0;

  apr_table_do(iterate_claim_map, iterator_data, conf->values->claim_map, NULL);
  return iterator_data->error;
}

int add_auth_header(request_rec *r, proxy_jwt_auth_config *conf) {
  jwt_t *token;
  apr_time_t start_time, timing_claim_time;
  char *token_str;
  int rv;

  /* NOTE: These functions return the err code, they don't set errno */
  start_time = apr_time_now();
  rv = jwt_new(&token);
  if(rv != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99909) "mod_proxy_jwt_auth: Error initializing JWT token: %s", strerror(rv));
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  rv = jwt_set_alg(token, conf->values->token_alg, conf->values->token_alg_key, conf->values->token_alg_key_len);
  if(rv != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99910) "mod_proxy_jwt_auth: Error setting JWT algorithm: %s", strerror(rv));
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(99915) "mod_proxy_jwt_auth: JWT initialization took %ld microseconds", (apr_time_now() - start_time));

  // Set timing claims
  timing_claim_time = apr_time_now();
  if(jwt_add_grant_int(token, "iat", apr_time_sec(timing_claim_time)) != 0 ||
     jwt_add_grant_int(token, "nbf", apr_time_sec(timing_claim_time)) != 0 ||
     jwt_add_grant_int(token, "exp", (apr_time_sec(timing_claim_time) + conf->values->token_duration)) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99911) "mod_proxy_jwt_auth: Error setting JWT timing claims");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  // Add env var claims
  if(map_env_claims(r, conf, token) != 0) {
    // This function logs errors inline
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(99916) "mod_proxy_jwt_auth: JWT claim operations took %ld microseconds", (apr_time_now() - timing_claim_time));

  // jwt_encode_str returns a pointer that needs to be free'd.
  token_str = jwt_encode_str(token);
  if(token_str == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99912) "mod_proxy_jwt_auth: Error encoding token");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  apr_table_setn(r->headers_in, conf->values->header_name, apr_psprintf(r->pool, "Bearer %s", token_str));

  jwt_free(token);
  free(token_str);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(99917) "mod_proxy_jwt_auth: JWT generation took %ld microseconds", (apr_time_now() - start_time));

  return OK;
}

/********** Handlers **********/
static int proxy_jwt_auth_handler(request_rec *r)
{
  proxy_jwt_auth_config *conf = merge_conf(r->pool,
					    ap_get_module_config(r->server->module_config, &proxy_jwt_auth_module),
					    ap_get_module_config(r->per_dir_config, &proxy_jwt_auth_module));
  int rv;

  if (conf->values->enabled == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(99913) "mod_proxy_jwt_auth: Disabled");
    return DECLINED;
  }

  rv = add_auth_header(r, conf);
  if (rv != OK)
    return rv;

  /* Decline the request as this module modifies but does not process the request*/
  return DECLINED;
}

static void proxy_jwt_auth_register_hooks(apr_pool_t *p)
{
  static const char * const aszPost[] = { "mod_proxy.c", NULL };
  ap_hook_handler(proxy_jwt_auth_handler, NULL, aszPost, APR_HOOK_FIRST);
}
