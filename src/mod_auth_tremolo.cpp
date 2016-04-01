/*
Copyright 2016 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <apr_strings.h>
#include <apr_md5.h>            /* for apr_password_validate */
#include <apr_base64.h>
#include <apr_lib.h>            /* for apr_isspace */
#include <apr_base64.h>         /* for apr_base64_decode et al */
#define APR_WANT_STRFUNC        /* for strcasecmp */
#include <apr_want.h>

#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>



#include <http_protocol.h>
#include <http_request.h>
#include <ap_provider.h>

#include <iostream>
#include <string>
#include <cstring>
#include <json/json.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <boost/date_time/gregorian/gregorian.hpp>
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/date_time/local_time_adjustor.hpp"
#include "boost/date_time/c_local_time_adjustor.hpp"
#include <boost/date_time.hpp>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace Json;
using namespace boost::gregorian;
using namespace boost::posix_time;
namespace bt = boost::posix_time;



#ifdef APLOG_USE_MODULE
extern "C" module AP_MODULE_DECLARE_DATA auth_tremolo_module;
APLOG_USE_MODULE(auth_tremolo);
#endif



static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

static std::string base64_decode(std::string const& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(
			encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_];
		in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2)
					+ ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4)
					+ ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30)
				>> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2]
				& 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++)
			ret += char_array_3[j];
	}

	return ret;
}

typedef struct {

	/* Name of the header storing the ticket */
	char *headerName;

	/* Name of the attribute in the ticket that has the userName */
	char *uidAttrName;

	/* AES Encryption Key */
	char *aesKey;

	/* Flag for if headers should be set */
	int setHeaders;

	/* Optionally ignore a uri and children */
	char *ignoreURI;



	char *dir;
} auth_tremolo_config_rec;

static void *create_auth_tremolo_dir_config(apr_pool_t *p, char *d) {
	auth_tremolo_config_rec *conf =
			(auth_tremolo_config_rec*) apr_pcalloc(p, sizeof(*conf));

	conf->dir = d;
	conf->headerName = "tremoloHeader";
	conf->headerName = "uid";
	conf->setHeaders = 1;
	conf->ignoreURI = NULL;

	return conf;
}

/* Configuration Hooks */
static const char *add_tremolo_header_name(cmd_parms *cmd, void *config,
		const char *arg) {
	auth_tremolo_config_rec *conf = (auth_tremolo_config_rec*) config;
	conf->headerName = arg;
	return NULL;
}

static const char *add_tremolo_uid_attribute_name(cmd_parms *cmd, void *config,
		const char *arg) {
	auth_tremolo_config_rec *conf = (auth_tremolo_config_rec*) config;
	conf->uidAttrName = arg;
	return NULL;
}

static const char *add_tremolo_aes_key(cmd_parms *cmd, void *config,
		const char *arg) {
	auth_tremolo_config_rec *conf = (auth_tremolo_config_rec*) config;

	int len = apr_base64_decode_len(arg);
	conf->aesKey = apr_palloc(cmd->pool, sizeof(char*) * len);
	apr_base64_decode(conf->aesKey, arg);

	return NULL;
}

static const char *add_tremolo_set_headers_key(cmd_parms *cmd, void *config,
		int arg) {
	auth_tremolo_config_rec *conf = (auth_tremolo_config_rec*) config;

	conf->setHeaders = arg;

	return NULL;
}

static const char *add_tremolo_ignoreuri(cmd_parms *cmd, void *config,
		const char *arg) {
	auth_tremolo_config_rec *conf = (auth_tremolo_config_rec*) config;

	int len = apr_base64_decode_len(arg);
	conf->ignoreURI = arg;


	return NULL;
}



static const command_rec
		auth_tremolo_cmds[] =
				{
								AP_INIT_ITERATE("TremoloHeaderName", add_tremolo_header_name, NULL, OR_AUTHCFG,
										"specify the name of the header containing the Tremolo Unison ticket"),

								AP_INIT_ITERATE("TremoloUidAttributeName", add_tremolo_uid_attribute_name, NULL, OR_AUTHCFG,
										"specify the name of the attribute containing the user's id in the ticket"),

								AP_INIT_ITERATE("TremoloEncodedKey", add_tremolo_aes_key, NULL, OR_AUTHCFG,
										"specify the base64 encoded AES key"),

								AP_INIT_FLAG("TremoloCreateHeaders", add_tremolo_set_headers_key, NULL, OR_AUTHCFG,
										"Should headers be created from the token"),

								AP_INIT_ITERATE("TremoloIgnoreURI", add_tremolo_ignoreuri, NULL, OR_AUTHCFG,
																		"Ignore a uri and all children"),


						{ NULL } };

extern "C" module AP_MODULE_DECLARE_DATA auth_tremolo_module;

static int iterate_func(void *req, const char *key, const char *value) {


    if (key == NULL || value == NULL || value[0] == '\0')
        return 1;
    request_rec *r = (request_rec *)req;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Env Variable : '%s'='%s'",
    				key,value);



    return 1;
}

static int last_mile(auth_tremolo_config_rec *conf, const char *decodedToken,
		request_rec *r) {

	const char *preReWrite;
	const char *isAuthd = apr_table_get(r->subprocess_env, "TREMOLO_REQ_AUTHD");
    const char *isAuthdRedir = apr_table_get(r->subprocess_env, "REDIRECT_TREMOLO_REQ_AUTHD");

	bool alreadyProcessed = false;

	if (isAuthd == NULL && isAuthdRedir == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Request not processed yet");
	}

	if ((isAuthd != NULL && strcmp(isAuthd,"true") == 0) || (isAuthdRedir != NULL && strcmp(isAuthdRedir,"true") == 0)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Request already authenticated");
		alreadyProcessed = true;
	}



	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "UID Attribute Name '%s'",
			conf->uidAttrName);
	Json::Value token;
	Json::Reader reader;

	bool parsingSuccessful = reader.parse(decodedToken, token);
	if (!parsingSuccessful) {
		// report to the user the failure and their locations in the document.

		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Failed to parse configuration '%s'",
				reader.getFormatedErrorMessages().c_str());
		return DECLINED;
	}

	string encodedIV = string(token.get("iv", "").asString());
	string encodedEnc = string(token.get("encryptedRequest", "").asString());

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"Encrypted Request Encoded : '%s'", encodedEnc.c_str());
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "IV Encoded : '%s'",
			encodedIV.c_str());

	string decodedIV = base64_decode(encodedIV);
	string decodedEncData = base64_decode(encodedEnc);

	int *len = (int *) apr_palloc(r->pool, sizeof(int));
	unsigned char *out = (unsigned char*) apr_palloc(r->pool,
			sizeof(unsigned char*) * 1024);

	EVP_CIPHER_CTX de;
	EVP_CIPHER_CTX_init(&de);
	EVP_DecryptInit_ex(&de, EVP_aes_256_cbc(), NULL,
			(unsigned char*) conf->aesKey, (unsigned char*) decodedIV.c_str());
	EVP_DecryptUpdate(&de, out, len, (unsigned char*) decodedEncData.c_str(),
			decodedEncData.length());

	int outlen = strlen(out) + 1;
	int toremove = out[outlen - 1];
	outlen -= toremove;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "out : '%u' / '%s'", outlen,
			out);

	//char *requestToken = malloc(sizeof(char*) * (outlen));
	//strcpy(requestToken,out);
	string requestToken = string((const char*) out, outlen);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "request token : '%s'",
			requestToken.c_str());

	//free(out);
	//free(len);

	Json::Value root;

	parsingSuccessful = reader.parse(requestToken, root);
	if (!parsingSuccessful) {
		// report to the user the failure and their locations in the document.
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Failed to parse configuration '%s'",
				reader.getFormatedErrorMessages().c_str());
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ID '%s'",
			root.get("id", "").asCString());
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Not Before '%s'",
			root.get("notBefore", "").asCString());
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Not After '%s'",
			root.get("notAfter", "").asCString());
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "URI '%s'",
			root.get("uri", "").asCString());

	string strLoginLevel = boost::lexical_cast<string>( root.get("loginLevel", "0").asInt() );

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Login Level '%s'",
			strLoginLevel.c_str());

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Login Chain '%s'",
			root.get("authChain", "").asCString());



	std::locale format = std::locale(std::locale::classic(),
			new bt::time_input_facet("%Y-%m-%dT%H:%M:%s%Z"));

	bt::ptime notBefore;
	bt::ptime notAfter;
	std::istringstream is(root.get("notBefore", "").asString());
	is.imbue(format);

	is >> notBefore;

	std::istringstream isx(root.get("notAfter", "").asString());
	isx.imbue(format);
	isx >> notAfter;

	ptime utc_now = second_clock::universal_time();

	if (  !((notBefore < utc_now) && (utc_now < notAfter))  && ! alreadyProcessed   ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Time Check Failed",
				requestToken.c_str());
		return DECLINED;
	}

	if (strcmp(r->uri, root.get("uri", "").asCString()) != 0) {
		preReWrite = apr_table_get(r->subprocess_env, "SCRIPT_URL");

		/*ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Pre-rewrite '%s'",
								preReWrite);

				apr_table_do(iterate_func, r, r->subprocess_env, NULL);*/

		if (! alreadyProcessed && (preReWrite == NULL || strcmp(root.get("uri", "").asCString(),preReWrite) != 0) ) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "URI Check Failed '%s'",
							r->uri);

			return DECLINED;
		}











	}

	//validated request, add flag
	apr_table_add(r->subprocess_env, "TREMOLO_REQ_AUTHD", "true");

	//set the login level header

	char *hval1 = apr_palloc(r->pool,sizeof(char*) * (strlen(strLoginLevel.c_str()) + 1));
	strcpy(hval1, strLoginLevel.c_str());
	apr_table_add(r->headers_in, "TREMOLO_LOGIN_LEVEL", hval1);

	//set the login chain header
	Json::Value loginChain = root["authChain"];
	char *hval2 = apr_palloc(r->pool,sizeof(char*) * (strlen(loginChain.asCString()) + 1));
	strcpy(hval2, loginChain.asCString());
	apr_table_add(r->headers_in, "TREMOLO_LOGIN_CHAIN", hval2);


	Json::Value attrs = root["attrs"];
	for (int i = 0; i < attrs.size(); i++) {
		int nameLen = strlen(attrs[i]["name"].asCString()) + 1;
		char *strName = apr_palloc(r->pool, sizeof(char*) * nameLen);
		strcpy(strName, attrs[i]["name"].asCString());
		if (strcmp(attrs[i]["name"].asCString(), conf->uidAttrName) == 0) {

			r->ap_auth_type = "TremoloLastMile";
			Json::Value vals = attrs[i]["values"];
			int index = 0;
			r->user = apr_palloc(r->pool,
					sizeof(char*) * (strlen(vals[index].asCString()) + 1));

			strcpy(r->user, vals[index].asCString());

		}

		if (conf->setHeaders) {

			Json::Value vals = attrs[i]["values"];

			string headerVal = string();

			for (int j = 0; j < vals.size(); j++) {
				int size = strlen(vals[j].asCString()) + 1;
				char *strVal = apr_palloc(r->pool, sizeof(char*) * size);
				strcpy(strVal, vals[j].asCString());
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
						"Adding Header '%s' '%s'", strName, strVal);
				headerVal.append(strVal);
				if (j + 1 < vals.size()) {
					headerVal.append(" ");
				}
			}

			char *hval = apr_palloc(r->pool,
					sizeof(char*) * (headerVal.size() + 1));
			strcpy(hval, headerVal.c_str());
			apr_table_add(r->headers_in, strName, hval);

		}

	}

	return OK;
}



/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */
static int authenticate_tremolo_user(request_rec *r) {

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "In mod_auth_tremolo");

	const char *headerValue, *current_auth;

	auth_tremolo_config_rec *conf =
			ap_get_module_config(r->per_dir_config,&auth_tremolo_module);

	/* Are we configured to be TremoloLastMile auth? */
	current_auth = ap_auth_type(r);
	if (!current_auth || strcasecmp(current_auth, "TremoloLastMile")) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Not the right authentication type");
		return DECLINED;
	}

	/* Check for the ignore uri */
	if (conf->ignoreURI != NULL) {
		int ignoreLen = strlen(conf->ignoreURI);
		if (strncmp(conf->ignoreURI,r->uri,ignoreLen) == 0) {
			/* this uri should be ignored */
			return OK;
		}
	}

	headerValue = apr_table_get(r->headers_in, conf->headerName);

	if (headerValue == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No header");
		return DECLINED;
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Raw Header : '%s'",
				headerValue);

		string encodedToken = string(headerValue);
		string decodedToken = base64_decode(encodedToken);

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Token : '%s'",
				decodedToken.c_str());
		return last_mile(conf, decodedToken.c_str(), r);
	}
}

static void register_hooks(apr_pool_t *p) {
	ap_hook_check_user_id(authenticate_tremolo_user, NULL, NULL,
			APR_HOOK_MIDDLE);
}


extern "C" {
module AP_MODULE_DECLARE_DATA auth_tremolo_module = { STANDARD20_MODULE_STUFF,
		create_auth_tremolo_dir_config								, /* dir config creater */
		NULL								, /* dir merger --- default is to override */
		NULL								, /* server config */
		NULL								, /* merge server config */
		auth_tremolo_cmds								, /* command apr_table_t */
register_hooks /* register hooks */
};
}
