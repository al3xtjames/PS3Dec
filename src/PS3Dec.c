/***********************************************************************/
/*                                                                     */
/*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE              */
/*                    Version 2, December 2004                         */
/*                                                                     */
/* Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>                    */
/*                                                                     */
/* Everyone is permitted to copy and distribute verbatim or modified   */
/* copies of this license document, and changing it is allowed as long */
/* as the name is changed.                                             */
/*                                                                     */
/*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE              */
/*   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION   */
/*                                                                     */
/*  0. You just DO WHAT THE FUCK YOU WANT TO.                          */
/*                                                                     */
/***********************************************************************/

/*to compile, link against polarssl and openmp*/

/*When defined, program calculates execution time*/
#define TIMERS

/*when defined, updates console title with stats*/
#define PROGRESS_REPORT

/*set how many threads encryption/decryption is split into*/
#define THREAD_COUNT 12

#define BUFFER_SIZE_SEC (4096)
#define BUFFER_SIZE (BUFFER_SIZE_SEC*2048)

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#define _FILE_OFFSET_BITS 64
#endif

#ifdef TIMERS
#include <time.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <omp.h>

#define EXIT_SUCCESS 0
#define EXIT_FAIL 1

int rev=5;

/*print error message and abort*/
void abort_err(char* desc)
{
  fprintf(stderr, "%s\n", desc);
  exit(EXIT_FAIL);
}

/*check fread*/
size_t fread_chk (void * ptr, size_t size, size_t count, FILE * stream )
{
  if(fread(ptr, size, count, stream)!=size*count)
    abort_err("ERROR: Failed to read from file");
  return size*count;
}
#define fread(a,b,c,d) fread_chk(a,b,c,d)

/*check fwrite*/
size_t fwrite_chk ( const void * ptr, size_t size, size_t count, FILE * stream )
{
  if(fwrite(ptr, size, count, stream)!=size*count)
    abort_err("ERROR: Failed to write to file");
  return size*count;
}
#define fwrite(a,b,c,d) fwrite_chk(a,b,c,d)

/*check malloc*/
void* malloc_chk(size_t size)
{
  void* ptr=malloc(size);
  if(ptr==NULL)
    abort_err("ERROR: Failed to allocate memory");
  return ptr;
}
#define malloc(x) malloc_chk(x)

/*convert 4 bytes in big-endian format, to an unsigned integer*/
unsigned int char_arr_BE_to_uint(unsigned char* arr)
{
  return arr[3] + 256*(arr[2] + 256*(arr[1] + 256*arr[0]));
}

/*convert binary to hex string*/
void char_arr_to_hex(unsigned char* arr, unsigned char* str, unsigned int arr_len);

/*print help*/
void help()
{
  fprintf(stderr, "Encrypt/Decrypt a PS3 disc image. Supports original images (if user supplies\n");
  fprintf(stderr, "the key) and 3k3y images.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: PS3Dec <mode> <type> [type_op] in [out]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "If out is not defined, name is in.something, as appropriate\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "<mode>: 'd' for decrypt\n");
  fprintf(stderr, "        'e' for encrypt\n");
  fprintf(stderr, "<type>: \"3k3y\" for a 3k3y image (requires no type_op)\n");
  fprintf(stderr, "        \"d1\"   says type_op is d1 in hex form (32 char ascii) BEFORE\n");
  fprintf(stderr, "               it's been processed into the actual decryption key\n");
  fprintf(stderr, "        \"key\"  says type_op is the actual key in hex form (32 char\n");
  fprintf(stderr, "               ascii), aka d1 AFTER it has been processed, aka disc_key\n");
  /*fprintf(stderr, "        \"file\" says type_op defines a file the key should be taken from\n");
  fprintf(stderr, "                 (first 16 bytes binary)\n");*/
  fprintf(stderr, "\n");
}

/*convert ascii hex string to binary key*/
int hex_to_key(char* pot_key, unsigned char* key);

/*reset the iv to a particular lba*/
void reset_iv(unsigned char* iv, unsigned int j)
{
  memset(iv, 0, 12);

  iv[12] = (j & 0xFF000000)>>24;
  iv[13] = (j & 0x00FF0000)>>16;
  iv[14] = (j & 0x0000FF00)>> 8;
  iv[15] = (j & 0x000000FF)>> 0;
}

/*check user input for errors*/
int sanatise_key(char* pot_key);

#define MODE_ENCRYPT MBEDTLS_AES_ENCRYPT
#define MODE_DECRYPT MBEDTLS_AES_DECRYPT
#define TYPE_3K3Y 0
#define TYPE_D1 1
#define TYPE_FILE 2
#define TYPE_KEY 3

/*aes variables for the data*/
mbedtls_aes_context** aes=NULL;
unsigned char* key=NULL;
unsigned char* iv=NULL;
char* burn=NULL;
unsigned char* sec0sec1=NULL;
unsigned int global_lba=0;

/*cyclicly swap pointers. Pointers must be in correct order and point within*/
/*same array 'base'*/
void swap_ptrs(unsigned char* base, unsigned char** r, unsigned char** w, unsigned char**p)
{
  if(p==NULL)
  {
    r[0]=base+((r[0]+BUFFER_SIZE)-base)%(2*BUFFER_SIZE);
    w[0]=base+((w[0]+BUFFER_SIZE)-base)%(2*BUFFER_SIZE);
  }
  else
  {
    r[0]=base+((r[0]+BUFFER_SIZE)-base)%(3*BUFFER_SIZE);
    w[0]=base+((w[0]+BUFFER_SIZE)-base)%(3*BUFFER_SIZE);
    p[0]=base+((p[0]+BUFFER_SIZE)-base)%(3*BUFFER_SIZE);
  }
}
/*variables here are from global*/
void process(unsigned char* data, int sector_count, int mode)
{
  int k;
  #pragma omp parallel for num_threads(THREAD_COUNT)
  for(k=0;k<sector_count;++k)
  {
    int id=omp_get_thread_num();
    reset_iv(&iv[16*id], global_lba+k);
    if(mbedtls_aes_crypt_cbc(aes[id], mode, 2048, &iv[16*id], &data[2048*k], &data[2048*k])!=0)
      abort_err(mode==MODE_ENCRYPT?"ERROR: AES encrypt failed":"ERROR: AES decrypt failed");
  }
  global_lba+=sector_count;
}

void open_output(FILE** out_file, char* in, char* out, int mode)
{
  char* burn;
  if(out==NULL)
  {
    burn=malloc(32768);
    if(strcmp(in, "-")==0)
      sprintf(burn, "out.%s", mode==MODE_ENCRYPT?"enc":"dec");
    else
      sprintf(burn, "%s.%s", in, mode==MODE_ENCRYPT?"enc":"dec");
    if( (out_file[0]=fopen(burn, "wb"))==NULL )
      abort_err("ERROR: Failed to open output file for writing");
    free(burn);
  }
  else
  {
    if(strcmp(out, "-")==0)
      out_file[0]=stdout;
    else
    {
      if( (out_file[0]=fopen(out, "wb"))==NULL )
        abort_err("ERROR: Failed to open output file for writing");
    }
  }
}

void open_input(FILE** in_file, char* in)
{
  if(strcmp(in, "-")==0)
    in_file[0]=stdin;
  else
  {
    if( (in_file[0]=fopen(in, "rb"))==NULL )
    {
      abort_err("ERROR: Failed to open input file for reading");
    }
  }
}

void progress(char* title)
{
#ifdef _WIN32
  SetConsoleTitle(title);
#else
  /*printf("%c]0;%s%c", '\033', title, '\007'); glitches output*/
#endif
}

void hex_fprintf(FILE *fp, unsigned char *buf, size_t len)
{
  int i;

  if (len <= 0)
    return;

  for (i = 0; i < len; i++) {
    if ((i > 0) && !(i % 16))
      fprintf(fp, "\n");

    fprintf(fp, "%02x ", buf[i]);
  }

  fprintf(fp, "\n");
}

int main(int argc, char*argv[])
{
  /*define execution path*/
  char mode;
  char type;

  /*io*/
  FILE* in_file=NULL;
  FILE* out_file=NULL;
  unsigned char* in=NULL;

  /*aes variables for the key*/
  mbedtls_aes_context* aes_d1=NULL;
  unsigned char key_d1[] = {0x38, 11, 0xcf, 11, 0x53, 0x45, 0x5b, 60, 120, 0x17, 0xab, 0x4f, 0xa3, 0xba, 0x90, 0xed};
  unsigned char iv_d1[] = {0x69, 0x47, 0x47, 0x72, 0xaf, 0x6f, 0xda, 0xb3, 0x42, 0x74, 0x3a, 0xef, 170, 0x18, 0x62, 0x87};

  /*loop variables*/
  unsigned int i;

  /*region variables*/
  char first=EXIT_SUCCESS;
  char plain=EXIT_SUCCESS;
  unsigned int regions;
  unsigned int region_last_sector;

  unsigned char* read_ptr;
  unsigned char* write_ptr;
  unsigned char* process_ptr;

  unsigned int num_blocks;
  unsigned int num_full_blocks;
  unsigned int curr_block;
  unsigned int partial_block_size;

#ifdef PROGRESS_REPORT
  char* title;
  unsigned int total_sectors;
#endif

#ifdef TIMERS
  time_t t_start, t_end;
  double time_taken;
#endif

#ifdef PROGRESS_REPORT
  title=malloc(4096);
#endif

#ifdef TIMERS
  time(&t_start);
#endif

#ifdef _WIN32
  if( _setmode ( _fileno ( stdout ), O_BINARY ) == -1 )
    abort_err("ERROR: Cannot set stdin to binary mode");
  if( _setmode ( _fileno ( stdin ), O_BINARY ) == -1 )
    abort_err("ERROR: Cannot set stdin to binary mode");
#endif

  fprintf(stderr, "PS3Dec r%d (compiled to use %d threads for enc/dec)\n\n", rev, THREAD_COUNT);

  if(argc<=1)
  {
    help();
    abort_err("ERROR: Not enough args");
  }

  if( argv[1][0]=='h' || argv[1][0]=='H' || memcmp(argv[1], "-h", 2)==0 || memcmp(argv[1], "-H", 2)==0 || memcmp(argv[1], "--h", 3)==0 || memcmp(argv[1], "--H", 3)==0 )
  {
    help();
    return 0;
  }

  if(argc<=3)
  {
    help();
    abort_err("ERROR: Not enough args");
  }

  if( argv[1][0]=='e' || argv[1][0]=='E' )
    mode=MODE_ENCRYPT;
  else if( argv[1][0]=='d' || argv[1][0]=='D' )
    mode=MODE_DECRYPT;
  else
  {
    fprintf(stderr, "Unsupported mode: '%s'\n", argv[1]);
    return 1;
  }

  key=malloc(16);

  /*handle divergent commandline*/
  if( argv[2][0]=='3' )
  {
    type=TYPE_3K3Y;
    if(argc!=4 && argc!=5)
      abort_err("ERROR: Incorrect arg count, check commandline for errors");
    open_input(&in_file, argv[3]);
    open_output(&out_file, argv[3], (argc==4?NULL:argv[4]), mode);
    /*get key*/
    sec0sec1=malloc(4096);

    fread(sec0sec1, 1, 4096, in_file);
    if(sec0sec1[0xf70]==0)
      abort_err("ERROR: Does not appear to be a 3k3y image\n");
    else if( (sec0sec1[0xf70]=='e' || sec0sec1[0xf70]=='E') && mode==MODE_ENCRYPT)
      abort_err("ERROR: 3k3y image appears to be encrypted already");
    else if( (sec0sec1[0xf70]=='d' || sec0sec1[0xf70]=='D') && mode==MODE_DECRYPT)
      abort_err("ERROR: 3k3y image appears to be decrypted already");
    else
      fprintf(stderr, "Input image successfully detected as 3k3y\n");
    memcpy(key, &sec0sec1[0xf80], 0x10);
  }
  else if( argv[2][0]=='d' || argv[2][0]=='D' )
  {
    type=TYPE_D1;
    /*get key*/
    if( strlen(argv[3])==34 )/*remove 0x if present*/
      argv[3]=&argv[3][2];
    if( strlen(argv[3])!=32 )
      abort_err("ERROR: D1 must be 32 hex characters in length");
    if( sanatise_key(argv[3])!=EXIT_SUCCESS )
      abort_err("ERROR: Supplied D1 contains invalid characters");
    if( hex_to_key(argv[3], key) !=EXIT_SUCCESS )
      abort_err("ERROR: hex string to char array key conversion failed");
  }
  else if( argv[2][0]=='k' || argv[2][0]=='K' )
  {
    type=TYPE_KEY;
    /*get key*/
    if( strlen(argv[3])==34 )/*remove 0x if present*/
      argv[3]=&argv[3][2];
    if( strlen(argv[3])!=32 )
      abort_err("ERROR: Key must be 32 hex characters in length");
    if( sanatise_key(argv[3])!=EXIT_SUCCESS )
      abort_err("ERROR: Supplied key contains invalid characters");
    if( hex_to_key(argv[3], key) !=EXIT_SUCCESS )
      abort_err("ERROR: hex string to char array key conversion failed");
  }
  /*else if( argv[2][0]=='f' || argv[2][0]=='F' )
  {
    type=TYPE_FILE;
    //get key
    if( (in_file=fopen(argv[3], "rb"))==NULL )
      abort_err("ERROR: Failed to open key input file for reading");
    fread(key, 1, 16, in_file);
    fclose(in_file);
  }*/
  else
  {
    fprintf(stderr, "Unsupported type: '%s'\n", argv[2]);
    return 1;
  }

  /*common init to non-3k3y types*/
  if( type==TYPE_D1 || type==TYPE_KEY || type==TYPE_FILE )/*do it like this even if TYPE_FILE has been removed, to possibly add it back later*/
  {
    if(argc!=5 && argc!=6)
      abort_err("ERROR: Incorrect arg count, check commandline for errors");
    open_input(&in_file, argv[4]);
    open_output(&out_file, argv[4], (argc==5?NULL:argv[5]), mode);
    sec0sec1=malloc(4096);
    fread(sec0sec1, 1, 4096, in_file);
  }

  /*convert d1 to decryption key if necessary*/
  if(type==TYPE_3K3Y || type==TYPE_D1 || type==TYPE_FILE )
  {
    aes_d1=malloc(sizeof(mbedtls_aes_context));
    if( mbedtls_aes_setkey_enc( aes_d1, key_d1, 128 )!=0 )
      abort_err("ERROR: AES encryption key initialisation failed for d1 -> key");
    if(mbedtls_aes_crypt_cbc(aes_d1, MBEDTLS_AES_ENCRYPT, 16, iv_d1, key, key)!=0)
      abort_err("ERROR: AES encrypt failed for d1 -> key");
    free(aes_d1);
  }
  fprintf(stdout, "Decryption key:");hex_fprintf(stdout, key, 16);

  /*initialise aes*/
  aes=malloc(sizeof(mbedtls_aes_context*)*THREAD_COUNT);
  i=0;
  while(i<THREAD_COUNT)
  {
    aes[i]=malloc(sizeof(mbedtls_aes_context));
    if(mode==MODE_ENCRYPT)
    {
      if( mbedtls_aes_setkey_enc( aes[i], key, 128 )!=0 )
        abort_err("ERROR: AES encryption key initialisation failed");
    }
    else
    {
      if( mbedtls_aes_setkey_dec( aes[i], key, 128 )!=0 )
        abort_err("ERROR: AES decryption key initialisation failed");
    }
    ++i;
  }

  iv=malloc(16*THREAD_COUNT);
  in=malloc(3*BUFFER_SIZE);/*thriple sized buffer for simultaneous io+processing*/
  /*read encryption layer from first sesector*/

  regions=(char_arr_BE_to_uint(sec0sec1)*2)-1;

#ifdef PROGRESS_REPORT
  total_sectors=1+char_arr_BE_to_uint(sec0sec1+12+((regions-1)*4));
#endif

  /*do every region*/
  i=0;
  while(i<regions)
  {
    region_last_sector=char_arr_BE_to_uint(sec0sec1+12+(i*4));
    region_last_sector-= (plain==EXIT_SUCCESS?0:1);
    fprintf(stderr, "%s sectors %8u to %8u\n", (plain==EXIT_SUCCESS?"   Copying":(mode==MODE_DECRYPT?"Decrypting":"Encrypting")), global_lba, region_last_sector);
    fflush(stdout);

    num_full_blocks =    (1+region_last_sector-global_lba)/BUFFER_SIZE_SEC;
    partial_block_size = (1+region_last_sector-global_lba)%BUFFER_SIZE_SEC;
    num_blocks=num_full_blocks+ (partial_block_size==0?0:1);

    if(plain==EXIT_SUCCESS)
    {
      /*multi-threaded plain region code*/
      read_ptr=&in[0];
      write_ptr=&in[BUFFER_SIZE];

      /*read first block of region*/
      if(first==EXIT_SUCCESS)
      {
        /*to avoid seeking*/
        memcpy(read_ptr, sec0sec1, 4096);
        fread(read_ptr+4096, 1, (num_full_blocks==0?2048*(partial_block_size-2):BUFFER_SIZE-4096), in_file);
      }
      else
        fread(read_ptr, 1, (num_full_blocks==0?2048*partial_block_size:BUFFER_SIZE), in_file);

      /*change 3k3y header in first region*/
      if(type==TYPE_3K3Y && first==EXIT_SUCCESS)
      {
        if((num_full_blocks==0?2048*partial_block_size:BUFFER_SIZE)>2048)
          memcpy(&read_ptr[0xf70], mode==MODE_ENCRYPT?"Encrypted 3K ISO":"Decrypted 3K ISO", 0x10);
        else
          abort_err("ERROR: First region should be at least 2 sectors, something's wrong");
      }
      first=EXIT_FAIL;
      swap_ptrs(in, &read_ptr, &write_ptr, NULL);

      curr_block=1;
      while(curr_block<num_blocks)
      {
#ifdef PROGRESS_REPORT
        sprintf(title, "PS3Dec r%d [%2u%%] [Region %2u/%2u]", rev, ((100*global_lba)/total_sectors), i+1, regions);
        progress(title);
#endif
        /*simultaneous read/write*/
        #pragma omp parallel num_threads(2)
        {
          /*thread 0 reads, thread 1 writes*/
          omp_get_thread_num()==0?fread(read_ptr, 1, (curr_block==num_full_blocks?2048*partial_block_size:BUFFER_SIZE), in_file):fwrite(write_ptr, 1, BUFFER_SIZE, out_file);
        }
        global_lba+=BUFFER_SIZE_SEC;
        swap_ptrs(in, &read_ptr, &write_ptr, NULL);
        ++curr_block;
      }
      /*write last block*/
      fwrite(write_ptr, 1, (partial_block_size==0?BUFFER_SIZE:2048*partial_block_size), out_file);
      global_lba+=(partial_block_size==0?BUFFER_SIZE_SEC:partial_block_size);
    }
    else
    {
      /*multi-threaded encrypted/decrypted region*/
      read_ptr=&in[0];
      write_ptr=&in[BUFFER_SIZE];
      process_ptr=&in[2*BUFFER_SIZE];

      if(num_blocks<3)
      {
        /*escape for small regions, do io serially*/
        curr_block=0;
        while(curr_block<num_blocks)
        {
#ifdef PROGRESS_REPORT
          sprintf(title, "PS3Dec r%d [%2u%%] [Region %2u/%2u]", rev, ((100*global_lba)/total_sectors), i+1, regions);
          progress(title);
#endif
          fread(read_ptr, 1, 2048*(curr_block==num_full_blocks?partial_block_size:BUFFER_SIZE_SEC), in_file);
          process(read_ptr, (curr_block==num_full_blocks?partial_block_size:BUFFER_SIZE_SEC), mode);
          fwrite(read_ptr, 1, 2048*(curr_block==num_full_blocks?partial_block_size:BUFFER_SIZE_SEC), out_file);
          ++curr_block;
        }
      }
      else
      {
        /*initial reading/processing to fill the buffers*/
        fread(read_ptr, 1, BUFFER_SIZE, in_file);
        swap_ptrs(in, &read_ptr, &write_ptr, &process_ptr);
        fread(read_ptr, 1, BUFFER_SIZE, in_file);
        process(process_ptr, BUFFER_SIZE_SEC, mode);
        swap_ptrs(in, &read_ptr, &write_ptr, &process_ptr);
        /*the meat of the work*/
        curr_block=2;
        while(curr_block<num_blocks)
        {
#ifdef PROGRESS_REPORT
          sprintf(title, "PS3Dec r%d [%2u%%] [Region %2u/%2u]", rev, ((100*global_lba)/total_sectors), i+1, regions);
          progress(title);
#endif
          #pragma omp parallel num_threads(3)
          {
            switch(omp_get_thread_num())
            {
              case 0:/*read*/
                fread(read_ptr, 1, 2048*(curr_block==num_full_blocks?partial_block_size:BUFFER_SIZE_SEC), in_file);
                break;
              case 1:/*write*/
                fwrite(write_ptr, 1, BUFFER_SIZE, out_file);
                break;
              case 2:/*process*/
                process(process_ptr, BUFFER_SIZE_SEC, mode);
                break;
            }
          }
          swap_ptrs(in, &read_ptr, &write_ptr, &process_ptr);
          ++curr_block;
        }
        /*last processing/writing to empty the buffers*/
        process(process_ptr, (partial_block_size==0?BUFFER_SIZE_SEC:partial_block_size), mode);
        fwrite(write_ptr, 1, BUFFER_SIZE, out_file);
        swap_ptrs(in, &read_ptr, &write_ptr, &process_ptr);
        fwrite(write_ptr, 1, 2048*(partial_block_size==0?BUFFER_SIZE_SEC:partial_block_size), out_file);
      }
    }
    plain = (plain+1)%2;
    ++i;
  }

#ifdef TIMERS
  time(&t_end);
  time_taken = difftime(t_end, t_start);
  fprintf(stderr, "\nExecution completed in %.0lf seconds\n\n", time_taken);
#endif

  /*cleanup*/
  free(key);
  i=0;
  while(i<THREAD_COUNT)
  {
    free(aes[i]);
    ++i;
  }
  free(aes);
  free(iv);
  free(in);
  free(sec0sec1);

  return EXIT_SUCCESS;
}

void char_arr_to_hex(unsigned char* arr, unsigned char* str, unsigned int arr_len)
{
  char hex[]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  unsigned int i=0;
  while(i<arr_len)
  {
    str[(i*2)  ]=hex[ (arr[i]>>4) & 0x0F ];
    str[(i*2)+1]=hex[ (arr[i]   ) & 0x0F ];
    ++i;
  }
}

int sanatise_key(char* pot_key)
{
  unsigned int i=1;
  /*weed out invalid characters*/
  while(i<48)
  {
    if(strchr(pot_key, i)!=NULL)
      return EXIT_FAIL;
    ++i;
  }
  i=58;
  while(i<65)
  {
    if(strchr(pot_key, i)!=NULL)
      return EXIT_FAIL;
    ++i;
  }
  i=71;
  while(i<97)
  {
    if(strchr(pot_key, i)!=NULL)
      return EXIT_FAIL;
    ++i;
  }
  i=103;
  while(i<127)
  {
    if(strchr(pot_key, i)!=NULL)
      return EXIT_FAIL;
    ++i;
  }
  if(strchr(pot_key, i)!=NULL)
    return EXIT_FAIL;

  /*to uppercase*/
  i=0;
  while(i<32)
  {
    switch(pot_key[i])
    {
      case 'a':
        pot_key[i]='A';
      break;
      case 'b':
        pot_key[i]='B';
      break;
      case 'c':
        pot_key[i]='C';
      break;
      case 'd':
        pot_key[i]='D';
      break;
      case 'e':
        pot_key[i]='E';
      break;
      case 'f':
        pot_key[i]='F';
      break;
    }
    ++i;
  }

  return EXIT_SUCCESS;
}

int hex_to_key(char* pot_key, unsigned char* key)
{
  /*sscanf crashes wine, so hack*/
  unsigned int count=0;
  char* tmp_key=NULL;
  tmp_key=malloc(32);
  count=0;
  while(count<32)
  {
    tmp_key[count] = pot_key[count]>57?pot_key[count]-55:pot_key[count]-48;
    ++count;
  }
  count=0;
  while(count<16)
  {
    key[count]=16*tmp_key[(count*2)];
    key[count]+=tmp_key[(count*2)+1];
    ++count;
  }
  /*sscanf
  char* pos = pot_key;
  unsigned int count = 0;
  while(count < 16)
  {
    if(sscanf(pos, "%2hhx", &key[count])!=1)
      return EXIT_FAIL;
    pos += 2;
    ++count;
  }*/
  return EXIT_SUCCESS;
}
