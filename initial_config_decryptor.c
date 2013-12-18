// Compilation
// On Windows:
// cl.exe /nologo /O2 /Oi /Oy- /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /TC /MT /GS- /Gy initial_config_decryptor.c /link /OUT:"initial_config_decryptor.exe" /NOLOGO /MANIFEST:NO /SUBSYSTEM:CONSOLE /MACHINE:X86 && del *.exp, *.lib, *.obj
// On Linux:
// gcc initial_config_decryptor.c -o initial_config_decryptor


#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>

unsigned char* read_file(char* filename, size_t* len)
{
	size_t buffer_len = 0;
	unsigned char* buffer = NULL;

	FILE * fl = fopen(filename, "rb");
	if(fl)
	{
		fseek(fl, 0, SEEK_END);
		*len = ftell(fl);
		fseek(fl, 0, SEEK_SET);
		buffer = (unsigned char*)calloc(*len, sizeof(unsigned char));
		buffer_len = fread(buffer, 1, *len, fl);
		if(buffer_len != *len)
		{
			*len = 0;
			free(buffer);
			buffer = NULL;
		}
		fclose(fl);
	}
	return buffer;
}

int write_buffer(char* filename, unsigned char* buffer, size_t buffer_len)
{
	FILE* fl = fopen(filename, "wb");
	size_t bytes_written = 0;
	if(fl)
	{
		bytes_written = fwrite(buffer, 1, buffer_len, fl);
		fclose(fl);
	}
	return buffer_len == bytes_written;
}

uint64_t decrypt8(uint32_t* encr_text, uint32_t* key)
{
	uint64_t result;
	uint32_t c = encr_text[0];
	uint32_t d = encr_text[1];
	uint32_t a = 0xCC623AF3; // (0x9E3779B9 * 0x0B) mod 2^32

	// 11 rounds
	while(a != 0)
	{
		uint32_t r1 = a;
		uint32_t r2 = c;

		r1 = (key[(a >> 11) & 0x03]) + a;
		r2 = ((c >> 5) ^ (c << 4)) + c;
		d -= (r1 ^ r2);

		a += 0x61C88647; // == - 0x9E3779B9

		r1 = key[a & 0x03] + a;
		r2 = ((d >> 5) ^ (d << 4)) + d;
		c -= (r1 ^ r2);
	}


	((uint32_t*)(&result))[0] = c;
	((uint32_t*)(&result))[1] = d;
	return result;
}

int decrypt_initial_configuration(unsigned char* c_text, size_t c_text_len, unsigned char* key, unsigned char** result_buf, size_t* result_buf_len)
{
	unsigned char * start;
	uint64_t result;
	uint32_t len = 0;
	uint64_t* clear;
	uint32_t k = 1;
	uint64_t res  = 0;

	start = c_text + key[0];
	printf("[~] Start offset: %d\n", key[0]);
	result = decrypt8((uint32_t*)start, (uint32_t*)key);

	if(((uint32_t*)(&result))[1] == 0xdeadbeef)
	{
		printf("[~] We've got DEADBEEF\n");
		len = ((uint32_t*)(&result))[0];
		printf("[~] Length: %d 8-byte blocks\n", len);
		if(len * 8 > c_text_len - key[0])
		{
			printf("[E] Length too big\n");
			printf("[~] Exit\n");
			return 0;
		}
	}
	else
	{
		printf("[E] We haven't got DEADBEEF\n");
		printf("[~] Exit\n");
		return 0;
	}

	clear = (uint64_t*)calloc(len, sizeof(uint64_t));
	clear[0] = result;

	k = 1;
	for(k = 1; k < len; ++k)
	{
		res = decrypt8((uint32_t*)(start + 8*k), (uint32_t*)key);
		clear[k] = res;
	}

	*result_buf = (unsigned char*)clear;
	*result_buf_len = len * sizeof(uint64_t);

	return 1;
}

void print_banner()
{
	printf("******************************************************\n");
	printf("*      Effusion initial configuration decryptor      *\n");
	printf("* Author: Evgeny Sidorov <e-sidorov@yandex-team.ru>  *\n");
	printf("******************************************************\n");
}

void print_usage(char* name)
{
	printf("Usage:\n");
	printf("\t%s <encrypted_config_file> <key_file> <output_file>\n", name);
}

int main(int argc, char** argv)
{
	unsigned char* buffer = NULL;
	size_t buffer_len = 0;
	unsigned char* key = NULL;
	size_t key_len = 0;
	unsigned char* result = NULL;
	size_t result_len = 0;
	int code = 0;
	size_t len = 0;
	int ret_code = EXIT_SUCCESS;

	print_banner();
	if(argc < 4)
	{
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	buffer = read_file(argv[1], &buffer_len);
	if(!buffer)
	{
		printf("[E] Couldn't read file with encrypted configuration: %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	if(buffer_len < 256)
	{
		printf("[E] File %s too small\n", argv[1]);
		free(buffer);
		return EXIT_FAILURE;
	}

	key = read_file(argv[2], &key_len);
	if(!key)
	{
		printf("[E] Couldn't read file with key: %s", argv[2]);
		free(buffer);
		return EXIT_FAILURE;
	}

	if(key_len < 16)
	{
		printf("[E] Key is too small (less than 16 bytes)");
		free(buffer);
		free(key);
		return EXIT_FAILURE;
	}

	if(decrypt_initial_configuration(buffer, buffer_len, key, &result, &result_len))
	{
		if(!write_buffer(argv[3], result, result_len))
		{
			printf("[E] Couldn't open output file: %s\n", argv[3]);
			printf("[~] Exit\n");
			ret_code = EXIT_FAILURE;
		}
		else
		{
			printf("[~] Decrypted configuration has been written to %s\n", argv[3]);
			printf("[~] Exit\n");
		}
		free(result);
	}

	free(buffer);
	free(key);

	return ret_code;
}
