/* $OpenBSD: apps.c,v 1.42 2017/01/21 09:29:09 deraadt Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "apps.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <openssl/rsa.h>

#define explicit_bzero bzero

typedef struct {
	const char *name;
	unsigned long flag;
	unsigned long mask;
} NAME_EX_TBL;

UI_METHOD *ui_method = NULL;

static int set_table_opts(unsigned long *flags, const char *arg,
    const NAME_EX_TBL *in_tbl);
static int set_multi_opts(unsigned long *flags, const char *arg,
    const NAME_EX_TBL *in_tbl);

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
/* Looks like this stuff is worth moving into separate function */
static EVP_PKEY *load_netscape_key(BIO *err, BIO *key, const char *file,
    const char *key_descrip, int format);
#endif

int
str2fmt(char *s)
{
	if (s == NULL)
		return FORMAT_UNDEF;
	if ((*s == 'D') || (*s == 'd'))
		return (FORMAT_ASN1);
	else if ((*s == 'T') || (*s == 't'))
		return (FORMAT_TEXT);
	else if ((*s == 'N') || (*s == 'n'))
		return (FORMAT_NETSCAPE);
	else if ((*s == 'S') || (*s == 's'))
		return (FORMAT_SMIME);
	else if ((*s == 'M') || (*s == 'm'))
		return (FORMAT_MSBLOB);
	else if ((*s == '1') ||
	    (strcmp(s, "PKCS12") == 0) || (strcmp(s, "pkcs12") == 0) ||
	    (strcmp(s, "P12") == 0) || (strcmp(s, "p12") == 0))
		return (FORMAT_PKCS12);
	else if ((*s == 'P') || (*s == 'p')) {
		if (s[1] == 'V' || s[1] == 'v')
			return FORMAT_PVK;
		else
			return (FORMAT_PEM);
	} else
		return (FORMAT_UNDEF);
}


int
dump_cert_text(BIO *out, X509 *x)
{
	char *p;

	p = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
	BIO_puts(out, "subject=");
	BIO_puts(out, p);
	free(p);

	p = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
	BIO_puts(out, "\nissuer=");
	BIO_puts(out, p);
	BIO_puts(out, "\n");
	free(p);

	return 0;
}

int
ui_open(UI *ui)
{
	return UI_method_get_opener(UI_OpenSSL()) (ui);
}

int
ui_read(UI *ui, UI_STRING *uis)
{
	const char *password;
	int string_type;

	if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
	    UI_get0_user_data(ui)) {
		string_type = UI_get_string_type(uis);
		if (string_type == UIT_PROMPT || string_type == UIT_VERIFY) {
                    password = (const char *)
			    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
			if (password && password[0] != '\0') {
				UI_set_result(ui, uis, password);
				return 1;
			}
		}
	}
	return UI_method_get_reader(UI_OpenSSL()) (ui, uis);
}

int
ui_write(UI *ui, UI_STRING *uis)
{
	const char *password;
	int string_type;

	if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
	    UI_get0_user_data(ui)) {
		string_type = UI_get_string_type(uis);
		if (string_type == UIT_PROMPT || string_type == UIT_VERIFY) {
                    password = (const char *)
			    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
			if (password && password[0] != '\0')
				return 1;
		}
	}
	return UI_method_get_writer(UI_OpenSSL()) (ui, uis);
}

int
ui_close(UI *ui)
{
	return UI_method_get_closer(UI_OpenSSL()) (ui);
}

int
password_callback(char *buf, int bufsiz, int verify, void *arg)
{
    PW_CB_DATA *cb_tmp = (PW_CB_DATA *) arg;
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *) cb_tmp;

	if (cb_data) {
		if (cb_data->password)
                    password = (const char *)cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}
	if (password) {
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}
	ui = UI_new_method(ui_method);
	if (ui) {
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui, prompt, ui_flags, buf,
			    PW_MIN_LENGTH, bufsiz - 1);
		if (ok >= 0 && verify) {
                    buff = (char *)malloc(bufsiz);
			ok = UI_add_verify_string(ui, prompt, ui_flags, buff,
			    PW_MIN_LENGTH, bufsiz - 1, buf);
		}
		if (ok >= 0)
			do {
				ok = UI_process(ui);
			} while (ok < 0 &&
			    UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff) {
			explicit_bzero(buff, (unsigned int) bufsiz);
			free(buff);
		}
		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1) {
                    fprintf(stderr, "User interface error\n");
			explicit_bzero(buf, (unsigned int) bufsiz);
			res = 0;
		}
		if (ok == -2) {
			fprintf(stderr, "aborted!\n");
			explicit_bzero(buf, (unsigned int) bufsiz);
			res = 0;
		}
		UI_free(ui);
		free(prompt);
	}
	return res;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio);

int
app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2)
{
	int same;

	if (!arg2 || !arg1 || strcmp(arg1, arg2))
		same = 0;
	else
		same = 1;
	if (arg1) {
		*pass1 = app_get_pass(err, arg1, same);
		if (!*pass1)
			return 0;
	} else if (pass1)
		*pass1 = NULL;
	if (arg2) {
		*pass2 = app_get_pass(err, arg2, same ? 2 : 0);
		if (!*pass2)
			return 0;
	} else if (pass2)
		*pass2 = NULL;
	return 1;
}

static char *
app_get_pass(BIO *err, char *arg, int keepbio)
{
	char *tmp, tpass[APP_PASS_LEN];
	static BIO *pwdbio = NULL;
	const char *errstr = NULL;
	int i;

	if (!strncmp(arg, "pass:", 5))
		return strdup(arg + 5);
	if (!strncmp(arg, "env:", 4)) {
		tmp = getenv(arg + 4);
		if (!tmp) {
			BIO_printf(err, "Can't read environment variable %s\n",
			    arg + 4);
			return NULL;
		}
		return strdup(tmp);
	}
	if (!keepbio || !pwdbio) {
		if (!strncmp(arg, "file:", 5)) {
			pwdbio = BIO_new_file(arg + 5, "r");
			if (!pwdbio) {
				BIO_printf(err, "Can't open file %s\n",
				    arg + 5);
				return NULL;
			}
		} else if (!strcmp(arg, "stdin")) {
			pwdbio = BIO_new_fp(stdin, BIO_NOCLOSE);
			if (!pwdbio) {
				BIO_printf(err, "Can't open BIO for stdin\n");
				return NULL;
			}
		} else {
			BIO_printf(err, "Invalid password argument \"%s\"\n",
			    arg);
			return NULL;
		}
	}
	i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
	if (keepbio != 1) {
		BIO_free_all(pwdbio);
		pwdbio = NULL;
	}
	if (i <= 0) {
		BIO_printf(err, "Error reading password from BIO\n");
		return NULL;
	}
	tmp = strchr(tpass, '\n');
	if (tmp)
		*tmp = 0;
	return strdup(tpass);
}

int
add_oid_section(BIO *err, CONF *conf)
{
	char *p;
	STACK_OF(CONF_VALUE) *sktmp;
	CONF_VALUE *cnf;
	int i;

	if (!(p = NCONF_get_string(conf, NULL, "oid_section"))) {
		ERR_clear_error();
		return 1;
	}
	if (!(sktmp = NCONF_get_section(conf, p))) {
		BIO_printf(err, "problem loading oid section %s\n", p);
		return 0;
	}
	for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
		cnf = sk_CONF_VALUE_value(sktmp, i);
		if (OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
			BIO_printf(err, "problem creating object %s=%s\n",
			    cnf->name, cnf->value);
			return 0;
		}
	}
	return 1;
}

static int
load_pkcs12(BIO *err, BIO *in, const char *desc, pem_password_cb *pem_cb,
    void *cb_data, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
	const char *pass;
	char tpass[PEM_BUFSIZE];
	int len, ret = 0;
	PKCS12 *p12;

	p12 = d2i_PKCS12_bio(in, NULL);
	if (p12 == NULL) {
		BIO_printf(err, "Error loading PKCS12 file for %s\n", desc);
		goto die;
	}
	/* See if an empty password will do */
	if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
		pass = "";
	else {
		if (!pem_cb)
			pem_cb = password_callback;
		len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
		if (len < 0) {
			BIO_printf(err, "Passpharse callback error for %s\n",
			    desc);
			goto die;
		}
		if (len < PEM_BUFSIZE)
			tpass[len] = 0;
		if (!PKCS12_verify_mac(p12, tpass, len)) {
			BIO_printf(err,
			    "Mac verify error (wrong password?) in PKCS12 file for %s\n", desc);
			goto die;
		}
		pass = tpass;
	}
	ret = PKCS12_parse(p12, pass, pkey, cert, ca);

die:
	if (p12)
		PKCS12_free(p12);
	return ret;
}

X509 *
load_cert(BIO *err, const char *file, int format, const char *pass,
    const char *cert_descrip)
{
	X509 *x = NULL;
	BIO *cert;

	if ((cert = BIO_new(BIO_s_file())) == NULL) {
		ERR_print_errors(err);
		goto end;
	}
	if (file == NULL) {
		setvbuf(stdin, NULL, _IONBF, 0);
		BIO_set_fp(cert, stdin, BIO_NOCLOSE);
	} else {
		if (BIO_read_filename(cert, file) <= 0) {
			BIO_printf(err, "Error opening %s %s\n",
			    cert_descrip, file);
			ERR_print_errors(err);
			goto end;
		}
	}

	if (format == FORMAT_ASN1) {
		x = d2i_X509_bio(cert, NULL);
	} else if (format == FORMAT_PEM)
		x = PEM_read_bio_X509_AUX(cert, NULL, password_callback, NULL);
	else if (format == FORMAT_PKCS12) {
		if (!load_pkcs12(err, cert, cert_descrip, NULL, NULL,
		    NULL, &x, NULL))
			goto end;
	} else {
		BIO_printf(err, "bad input format specified for %s\n",
		    cert_descrip);
		goto end;
	}

end:
	if (x == NULL) {
		BIO_printf(err, "unable to load certificate\n");
		ERR_print_errors(err);
	}
	BIO_free(cert);
	return (x);
}

EVP_PKEY *
load_key(BIO *err, const char *file, int format, int maybe_stdin,
    const char *pass, const char *key_descrip)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (file == NULL && (!maybe_stdin)) {
		BIO_printf(err, "no keyfile specified\n");
		goto end;
	}
	key = BIO_new(BIO_s_file());
	if (key == NULL) {
		ERR_print_errors(err);
		goto end;
	}
	if (file == NULL && maybe_stdin) {
		setvbuf(stdin, NULL, _IONBF, 0);
		BIO_set_fp(key, stdin, BIO_NOCLOSE);
	} else if (BIO_read_filename(key, file) <= 0) {
		BIO_printf(err, "Error opening %s %s\n",
		    key_descrip, file);
		ERR_print_errors(err);
		goto end;
	}
	if (format == FORMAT_ASN1) {
		pkey = d2i_PrivateKey_bio(key, NULL);
	} else if (format == FORMAT_PEM) {
		pkey = PEM_read_bio_PrivateKey(key, NULL, password_callback, &cb_data);
	}
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
	else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
		pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
	else if (format == FORMAT_PKCS12) {
		if (!load_pkcs12(err, key, key_descrip, password_callback, &cb_data,
		    &pkey, NULL, NULL))
			goto end;
	}
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA) && !defined (OPENSSL_NO_RC4)
	else if (format == FORMAT_MSBLOB)
		pkey = b2i_PrivateKey_bio(key);
	else if (format == FORMAT_PVK)
		pkey = b2i_PVK_bio(key, password_callback,
		    &cb_data);
#endif
	else {
		BIO_printf(err, "bad input format specified for key file\n");
		goto end;
	}
end:
	BIO_free(key);
	if (pkey == NULL) {
		BIO_printf(err, "unable to load %s\n", key_descrip);
		ERR_print_errors(err);
	}
	return (pkey);
}

EVP_PKEY *
load_pubkey(BIO *err, const char *file, int format, int maybe_stdin,
    const char *pass, const char *key_descrip)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (file == NULL && !maybe_stdin) {
		BIO_printf(err, "no keyfile specified\n");
		goto end;
	}
	key = BIO_new(BIO_s_file());
	if (key == NULL) {
		ERR_print_errors(err);
		goto end;
	}
	if (file == NULL && maybe_stdin) {
		setvbuf(stdin, NULL, _IONBF, 0);
		BIO_set_fp(key, stdin, BIO_NOCLOSE);
	} else if (BIO_read_filename(key, file) <= 0) {
		BIO_printf(err, "Error opening %s %s\n", key_descrip, file);
		ERR_print_errors(err);
		goto end;
	}
	if (format == FORMAT_ASN1) {
		pkey = d2i_PUBKEY_bio(key, NULL);
	}
	else if (format == FORMAT_ASN1RSA) {
		RSA *rsa;
		rsa = d2i_RSAPublicKey_bio(key, NULL);
		if (rsa) {
			pkey = EVP_PKEY_new();
			if (pkey)
				EVP_PKEY_set1_RSA(pkey, rsa);
			RSA_free(rsa);
		} else
			pkey = NULL;
	} else if (format == FORMAT_PEMRSA) {
		RSA *rsa;
		rsa = PEM_read_bio_RSAPublicKey(key, NULL, password_callback, &cb_data);
		if (rsa) {
			pkey = EVP_PKEY_new();
			if (pkey)
				EVP_PKEY_set1_RSA(pkey, rsa);
			RSA_free(rsa);
		} else
			pkey = NULL;
	}
	else if (format == FORMAT_PEM) {
		pkey = PEM_read_bio_PUBKEY(key, NULL, password_callback, &cb_data);
	}
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
	else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
		pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA)
	else if (format == FORMAT_MSBLOB)
		pkey = b2i_PublicKey_bio(key);
#endif
	else {
		BIO_printf(err, "bad input format specified for key file\n");
		goto end;
	}

end:
	BIO_free(key);
	if (pkey == NULL)
		BIO_printf(err, "unable to load %s\n", key_descrip);
	return (pkey);
}

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
static EVP_PKEY *
load_netscape_key(BIO *err, BIO *key, const char *file,
    const char *key_descrip, int format)
{
	EVP_PKEY *pkey;
	BUF_MEM *buf;
	RSA *rsa;
	const unsigned char *p;
	int size, i;

	buf = BUF_MEM_new();
	pkey = EVP_PKEY_new();
	size = 0;
	if (buf == NULL || pkey == NULL)
		goto error;
	for (;;) {
		if (!BUF_MEM_grow_clean(buf, size + 1024 * 10))
			goto error;
		i = BIO_read(key, &(buf->data[size]), 1024 * 10);
		size += i;
		if (i == 0)
			break;
		if (i < 0) {
			BIO_printf(err, "Error reading %s %s",
			    key_descrip, file);
			goto error;
		}
	}
	p = (unsigned char *) buf->data;
	rsa = d2i_RSA_NET(NULL, &p, (long) size, NULL,
	    (format == FORMAT_IISSGC ? 1 : 0));
	if (rsa == NULL)
		goto error;
	BUF_MEM_free(buf);
	EVP_PKEY_set1_RSA(pkey, rsa);
	return pkey;

error:
	BUF_MEM_free(buf);
	EVP_PKEY_free(pkey);
	return NULL;
}
#endif				/* ndef OPENSSL_NO_RC4 */

static int
load_certs_crls(BIO *err, const char *file, int format, const char *pass,
    const char *desc, STACK_OF(X509) **pcerts,
    STACK_OF(X509_CRL) **pcrls)
{
	int i;
	BIO *bio;
	STACK_OF(X509_INFO) *xis = NULL;
	X509_INFO *xi;
	PW_CB_DATA cb_data;
	int rv = 0;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (format != FORMAT_PEM) {
		BIO_printf(err, "bad input format specified for %s\n", desc);
		return 0;
	}
	if (file == NULL)
		bio = BIO_new_fp(stdin, BIO_NOCLOSE);
	else
		bio = BIO_new_file(file, "r");

	if (bio == NULL) {
		BIO_printf(err, "Error opening %s %s\n",
		    desc, file ? file : "stdin");
		ERR_print_errors(err);
		return 0;
	}
	xis = PEM_X509_INFO_read_bio(bio, NULL, password_callback, &cb_data);

	BIO_free(bio);

	if (pcerts) {
		*pcerts = sk_X509_new_null();
		if (!*pcerts)
			goto end;
	}
	if (pcrls) {
		*pcrls = sk_X509_CRL_new_null();
		if (!*pcrls)
			goto end;
	}
	for (i = 0; i < sk_X509_INFO_num(xis); i++) {
		xi = sk_X509_INFO_value(xis, i);
		if (xi->x509 && pcerts) {
			if (!sk_X509_push(*pcerts, xi->x509))
				goto end;
			xi->x509 = NULL;
		}
		if (xi->crl && pcrls) {
			if (!sk_X509_CRL_push(*pcrls, xi->crl))
				goto end;
			xi->crl = NULL;
		}
	}

	if (pcerts && sk_X509_num(*pcerts) > 0)
		rv = 1;

	if (pcrls && sk_X509_CRL_num(*pcrls) > 0)
		rv = 1;

end:
	if (xis)
		sk_X509_INFO_pop_free(xis, X509_INFO_free);

	if (rv == 0) {
		if (pcerts) {
			sk_X509_pop_free(*pcerts, X509_free);
			*pcerts = NULL;
		}
		if (pcrls) {
			sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
			*pcrls = NULL;
		}
		BIO_printf(err, "unable to load %s\n",
		    pcerts ? "certificates" : "CRLs");
		ERR_print_errors(err);
	}
	return rv;
}

STACK_OF(X509) *
load_certs(BIO *err, const char *file, int format, const char *pass,
    const char *desc)
{
	STACK_OF(X509) *certs;

	if (!load_certs_crls(err, file, format, pass, desc, &certs, NULL))
		return NULL;
	return certs;
}

STACK_OF(X509_CRL) *
load_crls(BIO *err, const char *file, int format, const char *pass,
    const char *desc)
{
	STACK_OF(X509_CRL) *crls;

	if (!load_certs_crls(err, file, format, pass, desc, NULL, &crls))
		return NULL;
	return crls;
}

#define X509V3_EXT_UNKNOWN_MASK		(0xfL << 16)
/* Return error for unknown extensions */
#define X509V3_EXT_DEFAULT		0
/* Print error for unknown extensions */
#define X509V3_EXT_ERROR_UNKNOWN	(1L << 16)
/* ASN1 parse unknown extensions */
#define X509V3_EXT_PARSE_UNKNOWN	(2L << 16)
/* BIO_dump unknown extensions */
#define X509V3_EXT_DUMP_UNKNOWN		(3L << 16)

#define X509_FLAG_CA (X509_FLAG_NO_ISSUER | X509_FLAG_NO_PUBKEY | \
			 X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION)

int
set_cert_ex(unsigned long *flags, const char *arg)
{
	static const NAME_EX_TBL cert_tbl[] = {
		{"compatible", X509_FLAG_COMPAT, 0xffffffffl},
		{"ca_default", X509_FLAG_CA, 0xffffffffl},
		{"no_header", X509_FLAG_NO_HEADER, 0},
		{"no_version", X509_FLAG_NO_VERSION, 0},
		{"no_serial", X509_FLAG_NO_SERIAL, 0},
		{"no_signame", X509_FLAG_NO_SIGNAME, 0},
		{"no_validity", X509_FLAG_NO_VALIDITY, 0},
		{"no_subject", X509_FLAG_NO_SUBJECT, 0},
		{"no_issuer", X509_FLAG_NO_ISSUER, 0},
		{"no_pubkey", X509_FLAG_NO_PUBKEY, 0},
		{"no_extensions", X509_FLAG_NO_EXTENSIONS, 0},
		{"no_sigdump", X509_FLAG_NO_SIGDUMP, 0},
		{"no_aux", X509_FLAG_NO_AUX, 0},
		{"no_attributes", X509_FLAG_NO_ATTRIBUTES, 0},
		{"ext_default", X509V3_EXT_DEFAULT, X509V3_EXT_UNKNOWN_MASK},
		{"ext_error", X509V3_EXT_ERROR_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
		{"ext_parse", X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
		{"ext_dump", X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
		{NULL, 0, 0}
	};
	return set_multi_opts(flags, arg, cert_tbl);
}

int
set_name_ex(unsigned long *flags, const char *arg)
{
	static const NAME_EX_TBL ex_tbl[] = {
		{"esc_2253", ASN1_STRFLGS_ESC_2253, 0},
		{"esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
		{"esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
		{"use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
		{"utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
		{"ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
		{"show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
		{"dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
		{"dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
		{"dump_der", ASN1_STRFLGS_DUMP_DER, 0},
		{"compat", XN_FLAG_COMPAT, 0xffffffffL},
		{"sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
		{"sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
		{"sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
		{"sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
		{"dn_rev", XN_FLAG_DN_REV, 0},
		{"nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
		{"sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
		{"lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
		{"align", XN_FLAG_FN_ALIGN, 0},
		{"oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
		{"space_eq", XN_FLAG_SPC_EQ, 0},
		{"dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
		{"RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
		{"oneline", XN_FLAG_ONELINE, 0xffffffffL},
		{"multiline", XN_FLAG_MULTILINE, 0xffffffffL},
		{"ca_default", XN_FLAG_MULTILINE, 0xffffffffL},
		{NULL, 0, 0}
	};
	return set_multi_opts(flags, arg, ex_tbl);
}

int
set_ext_copy(int *copy_type, const char *arg)
{
	if (!strcasecmp(arg, "none"))
		*copy_type = EXT_COPY_NONE;
	else if (!strcasecmp(arg, "copy"))
		*copy_type = EXT_COPY_ADD;
	else if (!strcasecmp(arg, "copyall"))
		*copy_type = EXT_COPY_ALL;
	else
		return 0;
	return 1;
}

int
copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
	STACK_OF(X509_EXTENSION) *exts = NULL;
	X509_EXTENSION *ext, *tmpext;
	ASN1_OBJECT *obj;
	int i, idx, ret = 0;

	if (!x || !req || (copy_type == EXT_COPY_NONE))
		return 1;
	exts = X509_REQ_get_extensions(req);

	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		ext = sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ext);
		idx = X509_get_ext_by_OBJ(x, obj, -1);
		/* Does extension exist? */
		if (idx != -1) {
			/* If normal copy don't override existing extension */
			if (copy_type == EXT_COPY_ADD)
				continue;
			/* Delete all extensions of same type */
			do {
				tmpext = X509_get_ext(x, idx);
				X509_delete_ext(x, idx);
				X509_EXTENSION_free(tmpext);
				idx = X509_get_ext_by_OBJ(x, obj, -1);
			} while (idx != -1);
		}
		if (!X509_add_ext(x, ext, -1))
			goto end;
	}

	ret = 1;

end:
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return ret;
}

static int
set_multi_opts(unsigned long *flags, const char *arg,
    const NAME_EX_TBL *in_tbl)
{
	STACK_OF(CONF_VALUE) *vals;
	CONF_VALUE *val;
	int i, ret = 1;

	if (!arg)
		return 0;
	vals = X509V3_parse_list(arg);
	for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
		val = sk_CONF_VALUE_value(vals, i);
		if (!set_table_opts(flags, val->name, in_tbl))
			ret = 0;
	}
	sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
	return ret;
}

static int
set_table_opts(unsigned long *flags, const char *arg,
    const NAME_EX_TBL *in_tbl)
{
	char c;
	const NAME_EX_TBL *ptbl;

	c = arg[0];
	if (c == '-') {
		c = 0;
		arg++;
	} else if (c == '+') {
		c = 1;
		arg++;
	} else
		c = 1;

	for (ptbl = in_tbl; ptbl->name; ptbl++) {
		if (!strcasecmp(arg, ptbl->name)) {
			*flags &= ~ptbl->mask;
			if (c)
				*flags |= ptbl->flag;
			else
				*flags &= ~ptbl->flag;
			return 1;
		}
	}
	return 0;
}

void
print_name(BIO *out, const char *title, X509_NAME *nm, unsigned long lflags)
{
	char *buf;
	char mline = 0;
	int indent = 0;

	if (title)
		BIO_puts(out, title);
	if ((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
		mline = 1;
		indent = 4;
	}
	if (lflags == XN_FLAG_COMPAT) {
		buf = X509_NAME_oneline(nm, 0, 0);
		BIO_puts(out, buf);
		BIO_puts(out, "\n");
		free(buf);
	} else {
		if (mline)
			BIO_puts(out, "\n");
		X509_NAME_print_ex(out, nm, indent, lflags);
		BIO_puts(out, "\n");
	}
}

X509_STORE *
setup_verify(BIO *bp, char *CAfile, char *CApath)
{
	X509_STORE *store;
	X509_LOOKUP *lookup;

	if (!(store = X509_STORE_new()))
		goto end;
	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (lookup == NULL)
		goto end;
	if (CAfile) {
		if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
			BIO_printf(bp, "Error loading file %s\n", CAfile);
			goto end;
		}
	} else
		X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
	if (lookup == NULL)
		goto end;
	if (CApath) {
		if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM)) {
			BIO_printf(bp, "Error loading directory %s\n", CApath);
			goto end;
		}
	} else
		X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

	ERR_clear_error();
	return store;

end:
	X509_STORE_free(store);
	return NULL;
}
