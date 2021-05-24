/* Copyright (C) 2019 Jeremy Thien <jeremy.thien@gmail.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <stdlib.h>
#include <jwt.h>

#include <string.h>
#include <errno.h>
#include <time.h>

int verify_jwt(char* pub_key_name, char* jwt_str)
{
	int exit_status = 0;
    jwt_alg_t opt_alg = JWT_ALG_ES256;
	int claims_count = 0;
	int i = 0;
    unsigned char key[10240];
	size_t key_len;
	FILE *fp_pub_key;

	int ret = 0;
	jwt_valid_t *jwt_valid;
	jwt_t *jwt = NULL;

	struct kv {
		char *key;
		char *val;
	} opt_claims[100];
	memset(opt_claims, 0, sizeof(opt_claims));

	/* Load pub key */
	fp_pub_key = fopen(pub_key_name, "r");
    if(fp_pub_key == NULL){
        int err = errno;
        return 0;
    }

	key_len = fread(key, 1, sizeof(key), fp_pub_key);
	fclose(fp_pub_key);
	key[key_len] = '\0';

	//printf("key_len -- %d ...\n", key_len);
	/* Load jwt */
	/*
	fp_jwt = fopen(opt_jwt_name, "r");
	jwt_len = fread(jwt_str, 1, sizeof(jwt_str), fp_jwt);
	fclose(fp_jwt);
	jwt_str[jwt_len] = '\0';
	*/

	/* Setup validation */
	ret = jwt_valid_new(&jwt_valid, opt_alg);
	if (ret != 0 || jwt_valid == NULL) {
		goto finish_valid;
	}

	jwt_valid_set_headers(jwt_valid, 1);
	jwt_valid_set_now(jwt_valid, time(NULL));
	for (i = 0; i < claims_count; i++) {
		jwt_valid_add_grant(jwt_valid, opt_claims[i].key, opt_claims[i].val);
	}

	/* Decode jwt */
	ret = jwt_decode(&jwt, jwt_str, key, key_len);
	if (ret != 0 || jwt == NULL) {
		exit_status = 1;
		goto finish;
	}

	/* Validate jwt */
	if (jwt_validate(jwt, jwt_valid) != 0) {
		jwt_dump_fp(jwt, stderr, 1);
		exit_status = 1;
		goto finish;
	}

	jwt_dump_fp(jwt, stdout, 1);

finish:
	jwt_free(jwt);
finish_valid:
	jwt_valid_free(jwt_valid);

	return exit_status;
}

