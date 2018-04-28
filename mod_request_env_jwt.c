/* 
**  mod_request_env_jwt: Remap request ENV vars and pass to proxied app as a
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

#define TOKEN_DEFAULT_DURATION 30

typedef struct {
  int enabled;
  int allow_missing;
  apr_table_t *claim_map;
  jwt_alg_t token_alg;
  unsigned char *token_alg_key;
  int token_alg_key_len;
  int token_duration;
} request_env_jwt_config;

typedef enum {
  dir_enabled,
  dir_allow_missing,
  dir_claim_map,
  dir_token_alg,
  dir_token_alg_key,
  dir_token_duration
} request_env_jwt_directive_enum;

// The following struct is for passing multiple variables into the claim_map apr_table_do iterator
typedef struct {
  request_env_jwt_config *conf;
  request_rec *r; /* Apache request struct */
  jwt_t *token;   /* JWT token to add claims to */
  int error;      /* Error flag: will be set to !0 when something is wrong */
} iterate_claim_map_data;

/****************************** Function Prototypes ******************************/
void load_key_file(apr_pool_t *pool, const char *path, request_env_jwt_config *conf);
jwt_alg_t str_to_jwt_alg(apr_pool_t *pool, const char *alg);

void *create_dir_conf(apr_pool_t *pool, char *context);
void *create_server_conf(apr_pool_t *pool, server_rec *s);
void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD);

static const char *set_config_single_arg(cmd_parms * cmd, void* config, const char* value);
static const char *set_config_double_arg(cmd_parms *cmd, void *config, const char *value1, const char *value2);

int print_request_env_keys(void* rec_v, const char *key, const char *value);
int iterate_claim_map(void* data_v, const char *env_key, const char *jwt_key);
int map_env_claims(request_rec *r, request_env_jwt_config *conf, jwt_t *token);
int add_auth_header(request_rec *r, request_env_jwt_config *conf);

static int request_env_jwt_handler(request_rec *r);
static void request_env_jwt_register_hooks(apr_pool_t *p);

/****************************** Apache Module API Directives ******************************/
static const command_rec request_env_jwt_directives[] = {
  AP_INIT_TAKE1("RequestEnvJwtEnabled",               set_config_single_arg, (void *)dir_enabled,        OR_ALL, "Enable or disable mod_request_env_jwt"),
  AP_INIT_TAKE1("RequestEnvJwtAllowMissing",          set_config_single_arg, (void *)dir_allow_missing,  OR_ALL, "Enable missing env var tolerance"),
  AP_INIT_TAKE2("RequestEnvJwtClaimMap",              set_config_double_arg, (void *)dir_claim_map,      OR_ALL, "Add a request env var ID to JWT claim ID map"),
  AP_INIT_TAKE1("RequestEnvJwtTokenAlgorithm",        set_config_single_arg, (void *)dir_token_alg,      OR_ALL, "Set JWT token algorithm"),
  AP_INIT_TAKE1("RequestEnvJwtTokenAlgorithmKeyPath", set_config_single_arg, (void *)dir_token_alg_key,  OR_ALL, "File path to the JWT token algorithm key file"),
  AP_INIT_TAKE1("RequestEnvJwtTokenDuration",         set_config_single_arg, (void *)dir_token_duration, OR_ALL, "JWT token duration in seconds"),
  { NULL }
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA request_env_jwt_module = {
    STANDARD20_MODULE_STUFF, 
    create_dir_conf,                /* create per-dir    config structures */
    merge_conf,                     /* merge  per-dir    config structures */
    create_server_conf,             /* create per-server config structures */
    merge_conf,                     /* merge  per-server config structures */
    request_env_jwt_directives,     /* table of config file commands       */
    request_env_jwt_register_hooks  /* register hooks                      */
};

/****************************** Functions ******************************/
/********** Configuration Helpers **********/
void load_key_file(apr_pool_t *pool, const char *path, request_env_jwt_config *conf) {
  // Not using apr_file methods as apr_file_read_full was returning "Bad Address" which is just confusing.
  FILE *fp;
  int bytes_read;

  fp = fopen(path, "r");
  if(fp == NULL) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, APLOGNO(99900) "mod_request_env_jwt: Unable to open key file %s: %s", path, strerror(errno));
    abort();
  }

  // Seek to the end and get the length
  fseek(fp, 0, SEEK_END);
  conf->token_alg_key_len = ftell(fp);
  rewind(fp);

  conf->token_alg_key = apr_pcalloc(pool, conf->token_alg_key_len);
  bytes_read = fread(conf->token_alg_key, 1, conf->token_alg_key_len, fp);
  fclose(fp);

  if(bytes_read != conf->token_alg_key_len) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, APLOGNO(99901) "mod_request_env_jwt: Error while reading key file %s: read %d/%d bytes", path, bytes_read, conf->token_alg_key_len);
    abort();
  }

  *(conf->token_alg_key + conf->token_alg_key_len) = '\0';
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

  ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, APLOGNO(99902) "mod_request_env_jwt: Invalid JWT algorithm: %s", alg);
  abort();
}

/********** Configuration Functions **********/
void *create_dir_conf(apr_pool_t *pool, char *context) {
  request_env_jwt_config *conf = apr_pcalloc(pool, sizeof(request_env_jwt_config));
  if(conf) {
    conf->enabled = 0;
    conf->allow_missing = 0;
    conf->claim_map = apr_table_make(pool, 0);
    conf->token_alg = JWT_ALG_NONE;
    conf->token_alg_key = NULL;
    conf->token_alg_key_len = 0;
    conf->token_duration = TOKEN_DEFAULT_DURATION;
  }
  return conf;
}

void *create_server_conf(apr_pool_t *pool, server_rec *s) {
  return create_dir_conf(pool, "server");
}

void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD) {
  request_env_jwt_config *base = (request_env_jwt_config *) BASE ; /* This is what was set in the parent context */
  request_env_jwt_config *add  = (request_env_jwt_config *) ADD ;   /* This is what is set in the new context */
  request_env_jwt_config *conf = apr_pcalloc(pool, sizeof(request_env_jwt_config));

  /* Merge configurations */
  conf->enabled = ( add->enabled == 0 ) ? base->enabled : add->enabled;
  conf->allow_missing = ( add->allow_missing == 0 ) ? base->allow_missing : add->allow_missing;
 
  conf->claim_map = apr_table_clone(pool, base->claim_map);
  apr_table_overlap(conf->claim_map, add->claim_map, APR_OVERLAP_TABLES_SET);

  conf->token_alg = (add->token_alg == JWT_ALG_NONE) ? base->token_alg : add->token_alg;
  if (add->token_alg_key_len > 0) {
    conf->token_alg_key = add->token_alg_key;
    conf->token_alg_key_len = add->token_alg_key_len;
  } else {
    conf->token_alg_key = base->token_alg_key;
    conf->token_alg_key_len = base->token_alg_key_len;
  }

  conf->token_duration = ( add->enabled == TOKEN_DEFAULT_DURATION ) ? base->token_duration : add->token_duration;
  return conf ;
}

static const char *set_config_single_arg(cmd_parms *cmd, void *config, const char *value) {
  request_env_jwt_config *conf;

  if(!cmd->path) {
    conf = (request_env_jwt_config *) ap_get_module_config(cmd->server->module_config, &request_env_jwt_module);
  } else {
    conf = (request_env_jwt_config *) config;
  }

  switch ((request_env_jwt_directive_enum)cmd->info) {
  case dir_enabled:
    if (!strcasecmp(value, "on"))
      conf->enabled = 1;
    else
      conf->enabled = 0;
    break;
  case dir_allow_missing:
    if (!strcasecmp(value, "on"))
      conf->allow_missing = 1;
    else
      conf->allow_missing = 0;
    break;
  case dir_token_alg:
    conf->token_alg = str_to_jwt_alg(cmd->pool, value);
    break;
  case dir_token_alg_key:
    load_key_file(cmd->pool, value, conf);
    break;
  case dir_token_duration:
    conf->token_duration = atoi(value);
    ap_log_perror(APLOG_MARK, APLOG_INFO, 0, cmd->pool, APLOGNO(99903) "mod_request_env_jwt: Token duration set to %d seconds", conf->token_duration);
    break;
  default:
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool, APLOGNO(99904) "mod_request_env_jwt: INTERNAL ERROR: Unknown directive 0x%02x passed to set_config_single_arg", (request_env_jwt_directive_enum)cmd->info);
    abort();
  }

  return NULL;
}

static const char *set_config_double_arg(cmd_parms *cmd, void *config, const char *value1, const char *value2) {
  request_env_jwt_config *conf;

  if(!cmd->path) {
    conf = (request_env_jwt_config *) ap_get_module_config(cmd->server->module_config, &request_env_jwt_module);
  } else {
    conf = (request_env_jwt_config *) config;
  }

  switch ((request_env_jwt_directive_enum)cmd->info) {
  case dir_claim_map:
    apr_table_set(conf->claim_map, value1, value2);
    break;
  default:
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool, APLOGNO(99905) "mod_request_env_jwt: INTERNAL ERROR: Unknown directive 0x%02x passed to set_config_double_arg", (request_env_jwt_directive_enum)cmd->info);
    abort();
  }

  return NULL;
}

/********** Handler Helpers **********/
int print_request_env_keys(void* rec_v, const char *key, const char *value) {
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, (request_rec *)(rec_v), APLOGNO(99906) "mod_request_env_jwt: Available key: %s", key);
  return 1;
}
  

int iterate_claim_map(void* data_v, const char *env_key, const char *jwt_key) {
  iterate_claim_map_data *data = (iterate_claim_map_data *)(data_v);
  const char *env_value;

  env_value = apr_table_get(data->r->subprocess_env, env_key);
  if (env_value == NULL) {
    if (data->conf->allow_missing != 1) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, data->r, APLOGNO(99907) "mod_request_env_jwt: Request env missing required key %s", env_key);
      apr_table_do(print_request_env_keys, data->r, data->r->subprocess_env, NULL);
      data->error = 1;
      return 0;
    }

    // Missing data is tolerated, but jwt_add_grant fails on null pointers.  Set the value to an empty string.
    env_value = "";
  }

  if (jwt_add_grant(data->token, jwt_key, env_value) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, data->r, APLOGNO(99908) "mod_request_env_jwt: Failed to add claim %s to the token", jwt_key);
    data->error = 1;
    return 0;
  }

  return 1;
}

int map_env_claims(request_rec *r, request_env_jwt_config *conf, jwt_t *token) {
  iterate_claim_map_data *iterator_data = apr_pcalloc(r->pool, sizeof(iterate_claim_map_data));

  iterator_data->r = r;
  iterator_data->conf = conf;
  iterator_data->token = token;
  iterator_data->error = 0;

  apr_table_do(iterate_claim_map, iterator_data, conf->claim_map, NULL);
  return iterator_data->error;
}

int add_auth_header(request_rec *r, request_env_jwt_config *conf) {
  jwt_t *token;
  long now = time(NULL);
  char *token_str;
  int rv;

  /* NOTE: These functions return the err code, they don't set errno */
  rv = jwt_new(&token);
  if(rv != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99909) "mod_request_env_jwt: Error initializing JWT token: %s", strerror(rv));
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  rv = jwt_set_alg(token, conf->token_alg, conf->token_alg_key, conf->token_alg_key_len);
  if(rv != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99910) "mod_request_env_jwt: Error setting JWT algorithm: %s", strerror(rv));
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  // Set timing claims
  if(jwt_add_grant_int(token, "iat", now) != 0 ||
     jwt_add_grant_int(token, "nbf", now) != 0 ||
     jwt_add_grant_int(token, "exp", (now + conf->token_duration)) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99911) "mod_request_env_jwt: Error setting JWT timing claims");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  // Add env var claims
  if(map_env_claims(r, conf, token) != 0) {
    // This function logs errors inline
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  
  // jwt_encode_str returns a pointer that needs to be free'd.
  token_str = jwt_encode_str(token);
  if(token_str == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(99912) "mod_request_env_jwt: Error encoding token");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  apr_table_setn(r->headers_in, "Authorization", apr_psprintf(r->pool, "Bearer %s", token_str));

  jwt_free(token);
  free(token_str);

  return OK;
}
  
/********** Handlers **********/
static int request_env_jwt_handler(request_rec *r)
{
  request_env_jwt_config *conf = merge_conf(r->pool,
					    ap_get_module_config(r->server->module_config, &request_env_jwt_module),
					    ap_get_module_config(r->per_dir_config, &request_env_jwt_module));
  int rv;

  if (conf->enabled != 1) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(99913) "mod_request_env_jwt: Disabled");
    return DECLINED;
  }


  rv = add_auth_header(r, conf);
  if (rv != OK)
    return rv;
    
  /* Decline the request as this module modifies but does not process the request*/
  return DECLINED;
}

static void request_env_jwt_register_hooks(apr_pool_t *p)
{
  static const char * const aszPost[] = { "mod_proxy.c", NULL };
  ap_hook_handler(request_env_jwt_handler, NULL, aszPost, APR_HOOK_FIRST);
}
