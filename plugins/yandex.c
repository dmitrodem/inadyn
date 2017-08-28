#include "plugin.h"
#include "jsmn.h"

#define YANDEX_GET_REQUEST					        \
        "GET %s "                                                       \
        "HTTP/1.1\r\n"                                                  \
	"Host: %s\r\n"                                                  \
	"PddToken: %s\r\n"                                              \
	"User-Agent: %s\r\n\r\n"

#define YANDEX_POST_REQUEST					        \
        "POST %s "                                                       \
        "HTTP/1.1\r\n"                                                  \
	"Host: %s\r\n"                                                  \
	"PddToken: %s\r\n"                                              \
	"User-Agent: %s\r\n"                                            \
	"Content-Length: %i\r\n"					\
	"Content-Type: application/x-www-form-urlencoded\r\n\r\n"	\
	"%s"


static int request  (ddns_t       *ctx,   ddns_info_t *info, ddns_alias_t *alias);
static int response (http_trans_t *trans, ddns_info_t *info, ddns_alias_t *alias);

static ddns_system_t plugin = {
	.name         = "default@pdd.yandex.ru",

	.request      = (req_fn_t)request,
	.response     = (rsp_fn_t)response,

	.checkip_name = DYNDNS_MY_IP_SERVER,
	.checkip_url  = DYNDNS_MY_CHECKIP_URL,
	.checkip_ssl  = DYNDNS_MY_IP_SSL,

	.server_name  = "pddimp.yandex.ru:443",
	.server_url   = "/dynamic/update.php"
};

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

static int yandex_success(const char *response) {
	jsmn_parser p;
	jsmntok_t t[1024];
	int r, i;
	
	jsmn_init(&p);
	r = jsmn_parse(&p, response, strlen(response), t, sizeof(t)/sizeof(t[0]));
	if (r < 0){
		logit(LOG_ERR, "Failed to parse JSON");
		return -1;
	}
	if ((r < 1) || (t[0].type != JSMN_OBJECT)) {
		logit(LOG_ERR, "JSON object expected");
		return -1;
	}

	for (i = 1; i < r-1; i++){
		if (jsoneq(response, &t[i], "success") == 0) {
			if (jsoneq(response, &t[i+1], "ok") == 0){
				return 1;
			}
		}
	}
	return 0;
}

static int yandex_find_record_id(const char *response, const char *subdomain){
	jsmn_parser parser;
	jsmntok_t t[1024];
	int r, i, j;

	int array_len = 0;
	int array_index = 0;
	int object_len = 0;
	int object_index = 0;

	enum {SUBDOMAIN_NONE,
	      SUBDOMAIN_KEYWORD,
	      SUBDOMAIN_VALUE} subdomain_search;

	enum {TYPE_NONE,
	      TYPE_KEYWORD,
	      TYPE_VALUE} type_search;
	
	int id_keyword_found = 0;
	int record_id = 0;

	char record_id_buf[128];
	
	enum {ST_FIND_RECORDS, ST_FIND_ARRAY,
	      ST_FIND_OBJECT,  ST_FIND_KEYWORD,
	      ST_FIND_VALUE,   ST_FINISH,
	      ST_ERROR} state = ST_FIND_RECORDS;
	
	jsmn_init(&parser);
	r = jsmn_parse(&parser, response, strlen(response), t, sizeof(t)/sizeof(t[0]));
	if (r < 0) {
		logit(LOG_ERR, "Failed to parse JSON");
		return -1;
	}
	if ((r < 1) || (t[0].type != JSMN_OBJECT)) {
		logit(LOG_ERR, "JSON object expected");
		return -1;
	}

	for (i = 1; i < r; i++){
		switch (state) {
		case ST_FIND_RECORDS:
			if (jsoneq(response, t+i, "records") == 0) {
				state = ST_FIND_ARRAY;
			}
			break;
		case ST_FIND_ARRAY:
			if (t[i].type == JSMN_ARRAY) {
				array_len = t[i].size;
				array_index = 0;
				state = ST_FIND_OBJECT;
			} else {
				state = ST_ERROR;
			}
			break;
		case ST_FIND_OBJECT:
			if (t[i].type == JSMN_OBJECT) {
				subdomain_search = SUBDOMAIN_NONE;
				type_search      = TYPE_NONE;
				id_keyword_found        = 0;
				record_id               = -1;
				object_len = t[i].size;
				object_index = 0;
				if (array_index == array_len) {
					state = ST_FINISH;
				} else {
					state = ST_FIND_KEYWORD;
				}
				array_index++;
			}
			break;
		case ST_FIND_KEYWORD:
			if (t[i].type == JSMN_STRING) {
				state = ST_FIND_VALUE;
				if (jsoneq(response, &t[i], "subdomain") == 0){
					subdomain_search = SUBDOMAIN_KEYWORD;
				}
				if (jsoneq(response, &t[i], "type") == 0){
					type_search = TYPE_KEYWORD;
				}
				if (strncmp("record_id", response + t[i].start, t[i].end - t[i].start) == 0) {
					id_keyword_found = 1;
				}
			}
			break;
		case ST_FIND_VALUE:
			if ((t[i].type == JSMN_STRING) || (t[i].type == JSMN_PRIMITIVE)) {
				if ((subdomain_search == SUBDOMAIN_KEYWORD) &&
				    (jsoneq(response, &t[i], subdomain)) == 0) {
					subdomain_search = SUBDOMAIN_VALUE;
				}
				if ((type_search == TYPE_KEYWORD) &&
				    (jsoneq(response, &t[i], "A")) == 0) {
					type_search = TYPE_VALUE;
				}
				if (id_keyword_found) {
					strncpy(record_id_buf, response + t[i].start, t[i].end - t[i].start);
					record_id = strtol(record_id_buf, NULL, 10);
					id_keyword_found = 0;
				}
				object_index++;
				if (object_index == object_len){
					if ((subdomain_search == SUBDOMAIN_VALUE) &&
					    (type_search      == TYPE_VALUE)) {
						goto finish;
					}
					state = ST_FIND_OBJECT;
				} else {
					state = ST_FIND_KEYWORD;
				}
			}
			break;
		case ST_ERROR:
			logit(LOG_ERR, "Some error\n");
			break;
		case ST_FINISH:
			break;
		default:
			break;
		}
		
	}
finish:
	logit(LOG_INFO, "Yandex DNS record_id = %i", record_id);
	return record_id;
}

static int request(ddns_t *ctx, ddns_info_t *info, ddns_alias_t *alias) {
	int rc = 0;
	http_t client;
	http_trans_t trans;
	char *buf, *s, *p;
	char url[256];
	int record_id;
	int content_length;
	do {
		TRY(http_construct(&client));

		http_set_port(&client, info->server_name.port);
		http_set_remote_name(&client, info->server_name.name);

		client.ssl_enabled = info->ssl_enabled;
		TRY(http_init(&client, "Sending update URL query"));		

		snprintf(url, sizeof(url),
			 "/api2/admin/dns/list?domain=%s",
			 info->creds.username);
		
		trans.req_len = snprintf(ctx->request_buf, ctx->request_buflen,
			 YANDEX_GET_REQUEST,
			 url, info->server_name.name, info->creds.password,
			 info->user_agent);
		trans.req = ctx->request_buf;
		trans.rsp = ctx->work_buf;
		trans.max_rsp_len = ctx->work_buflen - 1;

		rc  = http_transaction(&client, &trans);
		rc |= http_exit(&client);

		http_destruct(&client, 1);

		if (rc) {
			printf("SOME ERROR\n");
			break;
		}

		TRY(http_status_valid(trans.status));
		buf = strdup(trans.rsp_body);

		if (yandex_success(buf)) {
			record_id = yandex_find_record_id(buf, alias->name);
			logit(LOG_DEBUG, "Yandex PDD record_id = %i\n", record_id);

			TRY(http_construct(&client));

			http_set_port(&client, info->server_name.port);
			http_set_remote_name(&client, info->server_name.name);

			client.ssl_enabled = info->ssl_enabled;
			TRY(http_init(&client, "Sending update request"));
			
			if (record_id > 0){
				logit(LOG_INFO, "Updating record, id = %i", record_id);
				content_length = sprintf(url, "domain=%s&record_id=%i&content=%s",
					info->creds.username,
					record_id,
					alias->address);
				trans.req_len = snprintf(ctx->request_buf, ctx->request_buflen,
							 YANDEX_POST_REQUEST,
							 "/api2/admin/dns/edit",
							 info->server_name.name,
							 info->creds.password,
							 info->user_agent,
							 content_length,
							 url);

				
			} else {
				logit(LOG_INFO, "Creating record");
				printf("Create record\n");
				content_length = sprintf(url, "domain=%s&type=A&subdomain=%s&content=%s",
							 info->creds.username,
							 alias->name,
							 alias->address);
				trans.req_len = snprintf(ctx->request_buf, ctx->request_buflen,
							 YANDEX_POST_REQUEST,
							 "/api2/admin/dns/add",
							 info->server_name.name,
							 info->creds.password,
							 info->user_agent,
							 content_length,
							 url);
			}
			trans.req = ctx->request_buf;
			trans.rsp = ctx->work_buf;
			trans.max_rsp_len = ctx->work_buflen - 1;

			rc  = http_transaction(&client, &trans);
			rc |= http_exit(&client);

			http_destruct(&client, 1);

			if (yandex_success(trans.rsp_body)) {
				logit(LOG_INFO, "Record update/create succeeded");
			} else {
				logit(LOG_INFO, "Record update/create failed");
			}
		}
		free(buf);
		
	} while(0);
	return 0;
}

static int response(http_trans_t *trans, ddns_info_t *info, ddns_alias_t *alias) {
	return 0;
}

PLUGIN_INIT(plugin_init)
{
	plugin_register(&plugin);
}

PLUGIN_EXIT(plugin_exit)
{
	plugin_unregister(&plugin);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 *  company-clang-arguments: ("-I/home/dmitriy/Work/git/github.com/inadyn/include")
 * End:
 */
