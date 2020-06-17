#include <string.h>
#include <jni.h>
#include <stdio.h>
#include <time.h>
#include <android/log.h>
#include <unistd.h>
#include "libbswabe/bswabe.h"
#include "policy_lang.h"

#include <unistd.h>



double
to_milliseconds(struct timespec* time) 
{
	return (double)time->tv_sec*1000 + ((double)time->tv_nsec/1000000);
}

void
diff(struct timespec* res,struct timespec *start,struct timespec *end)
{
	if (res == NULL) return;
	
	res -> tv_sec = end -> tv_sec - start -> tv_sec;
	res -> tv_nsec = end -> tv_nsec - start -> tv_nsec;
	if (res -> tv_nsec < 0) 
	{
		res -> tv_nsec = res -> tv_nsec + 1000000000;
		res -> tv_sec --;
	}
}


JNIEXPORT jfloat
JNICALL Java_com_example_cpabe_NativeCPABE_getTick(JNIEnv *env,jobject thisObj)
{
	return sysconf(_SC_CLK_TCK);
}

JNIEXPORT jdouble 
JNICALL Java_com_example_cpabe_NativeCPABE_setup (JNIEnv *env, jobject thisObj,
		jstring pubFile,
		jstring mskFile,
		jint parameters_type)
{
	struct timespec start,d,end;
	clock_gettime(CLOCK_REALTIME,&start);
   
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;

	bswabe_setup(&pub,&msk,parameters_type);


	const char *pub_file = (*env) -> GetStringUTFChars(env, pubFile, 0);
	const char *msk_file = (*env) -> GetStringUTFChars(env, mskFile, 0);

	spit_file(pub_file, bswabe_pub_serialize(pub), 1);
	spit_file(msk_file, bswabe_msk_serialize(msk), 1);

		// Release Strings
	(*env) -> ReleaseStringUTFChars(env,pubFile,pub_file);
	(*env) -> ReleaseStringUTFChars(env,mskFile,msk_file);
	
	// Return the total execution time
	clock_gettime(CLOCK_REALTIME,&end);
	diff(&d,&start,&end);	
	return to_milliseconds(&d);

}


JNIEXPORT jdouble 
JNICALL Java_com_example_cpabe_NativeCPABE_keygen (JNIEnv *env, jobject thisObj, 
	jstring pubFile, 
	jstring mskFile, 
	jstring prvFile,
	jstring jattributes,
	jint jnum_attr)

{
	// Retrive the number of attributes
	int num_attr = (int) jnum_attr;//(*env) -> GetArrayLength(env,attributes);
	// Initialize the array of attributes
	char **c_attrs = 0;
	// Allocate
	c_attrs = malloc((num_attr + 1) * sizeof(char*));
	
/*	short int j = 0;*/
/*	for (;j < num_attr;j++) */
/*	{*/
/*		jobject el = (*env) -> GetObjectArrayElement(env,attributes, j);*/
/*		char* attribute = (char*) (*env) -> GetStringUTFChars(env, (jstring) el,0);*/
/*		c_attrs[j] = attribute;*/
/*	}*/
	
	const char *attributes = (*env) -> GetStringUTFChars(env, jattributes, 0);
	
	char* attributes_split = strdup(attributes);
	char* token = strsep(&attributes_split, " ");
	short int j = 0;
	while (token != NULL) {
		c_attrs[j] = token;
		token = strsep(&attributes_split, " ");
		j++;
	}
	
	
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	bswabe_prv_t* prv;

	// String conversion: jstring --> const char*
	const char *pub_file = (*env) -> GetStringUTFChars(env, pubFile, 0);
	const char *msk_file = (*env) -> GetStringUTFChars(env, mskFile, 0);
	const char *prv_file = (*env) -> GetStringUTFChars(env, prvFile, 0);
	
	// Retrive public key and master key from file
	GByteArray* pb = (GByteArray*) suck_file(pub_file);
	GByteArray* ms = (GByteArray*) suck_file(msk_file);

	pub = bswabe_pub_unserialize(pb, 1);
	msk = bswabe_msk_unserialize(pub, ms, 1);

	struct timespec start,d,end;
	clock_gettime(CLOCK_REALTIME,&start);

	// Generate the private key corresponding to the given attributes
	prv = bswabe_keygen(pub, msk, c_attrs,num_attr);
	
	// Return the total execution time
	clock_gettime(CLOCK_REALTIME,&end);
	diff(&d,&start,&end);	
	
	// Serialize the private key into a file
	spit_file(prv_file, bswabe_prv_serialize(prv), 1);
	
	// Clean everything:
/*	bswabe_prv_free(prv);*/
	free(c_attrs);
	bswabe_pub_free(pub);
	
	// Release Strings
	(*env) -> ReleaseStringUTFChars(env,pubFile,pub_file);
	(*env) -> ReleaseStringUTFChars(env,mskFile,msk_file);
	(*env) -> ReleaseStringUTFChars(env,prvFile,prv_file);
	(*env) -> ReleaseStringUTFChars(env,jattributes,attributes);
	
	return to_milliseconds(&d);
	
}


JNIEXPORT jdouble 
JNICALL Java_com_example_cpabe_NativeCPABE_enc (JNIEnv *env, jobject thisObj, 
	jstring pubFile, 
	jstring jpolicy,
	jstring inFile) 
{
	int keep = 1;
	
	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	int file_len;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;

	const char *pub_file 	= (*env) -> GetStringUTFChars(env, pubFile, 0);
	const char *policy 		= (*env) -> GetStringUTFChars(env, jpolicy, 0);
	const char* in_file  	= (*env) -> GetStringUTFChars(env, inFile, 0);
	char* out_file 			= g_strdup_printf("%s.cpabe", in_file);

	policy = parse_policy_lang((char*)policy);

	pub = bswabe_pub_unserialize((GByteArray*) suck_file(pub_file), 1);


	struct timespec start,d,end;
	clock_gettime(CLOCK_REALTIME,&start);
	
 	if( !(cph = bswabe_enc(pub, m, (char*)policy)) )
 	{
 		__android_log_print(ANDROID_LOG_VERBOSE, "ABE", "%s",bswabe_error());
 		return 0.0;
 	}
 	
 	// Return the time needed to encrypt
	clock_gettime(CLOCK_REALTIME,&end);
	diff(&d,&start,&end);	
 	
	cph_buf = bswabe_cph_serialize(cph);
	plt = (GByteArray*) suck_file(in_file);
	file_len = plt->len;
	
	__android_log_print(ANDROID_LOG_VERBOSE,"ABE", "File length = %d",file_len);
	
	aes_buf = (GByteArray*) aes_128_cbc_encrypt(plt, m);
	g_byte_array_free(plt, 1);
	element_clear(m);

	write_cpabe_file(out_file, cph_buf, file_len, aes_buf);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);

	// Release Strings
	(*env) -> ReleaseStringUTFChars(env,pubFile,pub_file);
	(*env) -> ReleaseStringUTFChars(env,jpolicy,policy);
	(*env) -> ReleaseStringUTFChars(env,inFile,in_file);

	bswabe_cph_free(cph);
	bswabe_pub_free(pub);	

	return to_milliseconds(&d);
}


JNIEXPORT jdouble 
JNICALL Java_com_example_cpabe_NativeCPABE_dec (JNIEnv *env, jobject thisObj, 
	jstring pubFile, 
	jstring prvFile, 
	jstring inFile,
	jstring outFile) 
{
	bswabe_pub_t* pub;
	bswabe_prv_t* prv;
	int file_len;
	GByteArray* aes_buf;
	GByteArray* plt;
	GByteArray* cph_buf;
	bswabe_cph_t* cph;
	element_t m;

	int   keep       = 1;

	struct timespec start,d,end;

	const char *pub_file 	= (*env) -> GetStringUTFChars(env, pubFile, 0);
	const char *prv_file 	= (*env) -> GetStringUTFChars(env, prvFile, 0);
	const char* in_file  	= (*env) -> GetStringUTFChars(env, inFile, 0);
	const char* out_file	= (*env) -> GetStringUTFChars(env, outFile, 0);

	pub = bswabe_pub_unserialize((GByteArray*) suck_file(pub_file), 1);
	prv = bswabe_prv_unserialize(pub, (GByteArray*) suck_file(prv_file), 1);

	read_cpabe_file(in_file, &cph_buf, &file_len, &aes_buf);

	cph = bswabe_cph_unserialize(pub, cph_buf, 1);
	
	clock_gettime(CLOCK_REALTIME,&start);

	if( !bswabe_dec(pub, prv, cph, m) )
	{
		__android_log_print(ANDROID_LOG_VERBOSE, "ABE", "%s",bswabe_error());
 		return 0.0;
	}
	
	// Return the time needed to decrypt
	clock_gettime(CLOCK_REALTIME,&end);
	
		
	plt = (GByteArray*) aes_128_cbc_decrypt(aes_buf, m);
	g_byte_array_set_size(plt, file_len);
	spit_file(out_file, plt, 1);
	
	unlink(in_file);

	element_clear(m);

	(*env) -> ReleaseStringUTFChars(env,pubFile,pub_file);
	(*env) -> ReleaseStringUTFChars(env,prvFile,prv_file);
	(*env) -> ReleaseStringUTFChars(env,inFile,in_file);
	(*env) -> ReleaseStringUTFChars(env,outFile,out_file);
	
	g_byte_array_free(aes_buf, 1);
/*	g_byte_array_free(plt, 1);*/
/*	g_byte_array_free(cph_buf, 1);*/

	bswabe_cph_free(cph);
/*	bswabe_pub_free(pub);*/
	
	
	diff(&d,&start,&end);	
	return to_milliseconds(&d);
}

