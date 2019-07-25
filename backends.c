/*
 * Copyright (c) 2014 Jan-Piet Mens <jp@mens.de>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions
 * in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. Neither the name of mosquitto
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "backends.h"
 #include "mosquitto.h"

/*
 * Search through `in' for tokens %c (clientid) and %u (username); build a
 * new malloc'd string at `res' with those tokens interpolated into it.
 */

void t_expand(const char *clientid, const char *username, const char *in, char **res)
{
	const char *s;
	char *work, *wp;
	int c_specials = 0, u_specials = 0, len;
	const char *ct, *ut;

	ct = (clientid) ? clientid : "";
	ut = (username) ? username : "";

	for (s = in; s && *s; s++) {
		if (*s == '%' && (*(s + 1) == 'c'))
			c_specials++;
		if (*s == '%' && (*(s + 1) == 'u'))
			u_specials++;
	}
	len = strlen(in) + 1;
	len += strlen(clientid) * c_specials;
	len += strlen(username) * u_specials;

	if ((work = malloc(len)) == NULL) {
		*res = NULL;
		return;
	}
	for (s = in, wp = work; s && *s; s++) {
		*wp++ = *s;
		if (*s == '%' && (*(s + 1) == 'c')) {
			*--wp = 0;
			strcpy(wp, ct);
			wp += strlen(ct);
			s++;
		}
		if (*s == '%' && (*(s + 1) == 'u')) {
			*--wp = 0;
			strcpy(wp, ut);
			wp += strlen(ut);
			s++;
		}
	}
	*wp = 0;

	*res = work;
}



/*
 * Compares an ACL topic filter with a requested subscribe filter to see if the subscription is allowed.
 * Sets *result to 1 if a match is found and false otherwise.
 */

int mosquitto_auth_sub_topic_matches_acl(const char *acl_topic, const char *req_topic, int *result)
{
	if(!result) {
		*result = FALSE;
		return MOSQ_ERR_INVAL;
	}

	if(!req_topic || !acl_topic) {
		*result = FALSE;
		return MOSQ_ERR_INVAL;
	}

	if(mosquitto_sub_topic_check(req_topic) != MOSQ_ERR_SUCCESS) {
		*result = FALSE;
		return MOSQ_ERR_INVAL;
	}

	if(mosquitto_sub_topic_check(acl_topic) != MOSQ_ERR_SUCCESS) {
		*result = FALSE;
		return MOSQ_ERR_INVAL;
	}

	if((*req_topic == '$' && *acl_topic != '$') || (*acl_topic == '$' && *req_topic != '$')) {
		*result = FALSE;
		return MOSQ_ERR_SUCCESS;
	}

	while(*req_topic && *acl_topic) {
		int check_equiv;

		//Process the # if it exists here.
		if(*acl_topic == '#') {
			//No need to check any further. The ACL has a #.
			*result = TRUE;
			return MOSQ_ERR_SUCCESS;
		} else if(*req_topic == '#') {
			//The user subscribed with a #, but the ACL does not allow that.
			*result = FALSE;
			return MOSQ_ERR_SUCCESS;
		}

		//Process the + if it exists here.
		if(*req_topic == '+') {
			//The subscription includes a single-level wild card. Check to see if that is allowed.
			if(*acl_topic == '+') {
				//The ACL allows for a + here. We need to move on to the next level without checking for equivalence.
				check_equiv = FALSE;
			} else {
				//The ACL doesn't allow for a + in this position.
				*result = FALSE;
				return MOSQ_ERR_SUCCESS;
			}
		} else {
			//We are just looking at normal subscription level.
			//If the ACL has a single level wildcard, no need to check anything else at this level.
			if(*acl_topic == '+') {
				//The ACL allows for a + here. We need to move on to the next level without checking for equivalence.
				check_equiv = FALSE;
			} else {
				//No wildcards. We need to compare to make sure the topic level for both topic filters are identical.
				check_equiv = TRUE;
			}
		}

		//Get the length of the current sub topic level.
		int sub_level_length = 0;
		while(req_topic[sub_level_length] && (req_topic[sub_level_length] != '/')) {
			sub_level_length++;
		}

		//Get the length of the current acl topic level.
		int acl_level_length = 0;
		while(acl_topic[acl_level_length] && (acl_topic[acl_level_length] != '/')) {
			acl_level_length++;
		}

		//If we need to check for equivalency, do so.
		if(check_equiv) {
			//First check to see if the lengths of the levels are identical. If not, we know we don't have a match.
			if(sub_level_length != acl_level_length) {
				*result = FALSE;
				return MOSQ_ERR_SUCCESS;
			}

			//Lengths are the same, so we need to check the contents.
			if(memcmp(req_topic, acl_topic, sub_level_length)) {
				*result = FALSE;
				return MOSQ_ERR_SUCCESS;
			}
		} else {
		}

		//Increment pointers
		req_topic += sub_level_length;
		acl_topic += acl_level_length;

		//If we haven't incremented to the null terminator, go one more to get past the '/'.
		// Only do this if both topics have not reached the end to avoid covering up situation
		// where one topic is longer than the other.
		if(*req_topic && *acl_topic) {
			req_topic++;
			acl_topic++;
		}
	}


	//If we hit the null terminator on one and not the other, we don't have a match.
	if((*req_topic != 0) ^ (*acl_topic != 0))
	{
		*result = FALSE;
		return MOSQ_ERR_SUCCESS;
	}

	//Topics match.
	*result = TRUE;
	return MOSQ_ERR_SUCCESS;
}
