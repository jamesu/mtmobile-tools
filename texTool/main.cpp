//
//  main.cpp
//  decryptArcTool
//
//  Created by MangoFusion on 17/09/2014.
//
//

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>

#include <sys/stat.h>
#include <unistd.h>

#include "PVRTDecompress.h"
#include "stb_image_aug.h"

void printUsage()
{
   printf("texTool\nUsage:\n\\ttexTool d infile outfile.tga\n");
}

#pragma pack(1)
typedef struct TexHeaderStruct
{
   unsigned int magic;
   unsigned char version; // 7
   
   unsigned char unknown0[3];
   
   //unsigned char format;
   
   unsigned char unknown4[4];
   
   unsigned short size;
   unsigned char unknown8;
   unsigned char flags;
   
} TexHeaderStruct;
#pragma pack()

class Stream
{
public:
   Stream()
   {
      
   }
   
   virtual ~Stream()
   {
   }
   
   virtual unsigned int read(int numBytes, void* data) = 0;
   virtual unsigned int write(int numBytes, void* data) = 0;
   
   virtual void setStreamPos(unsigned int pos) = 0;
   virtual void advanceStreamPos(unsigned int pos) = 0;
   virtual unsigned int getStreamPos() = 0;
   virtual unsigned int getStreamSize() = 0;
   virtual bool isEOF() = 0;
};

class FileStream : public Stream
{
public:
   FileStream() :
   mFP(0)
   {
   }
   
   virtual ~FileStream()
   {
      close();
   }
   
   bool open(const char *path, const char *mode)
   {
      mFP = fopen(path, mode);
      return mFP != NULL;
   }
   
   void close()
   {
      if (mFP)
         fclose(mFP);
      mFP = NULL;
   }
   
   virtual unsigned int read(int numBytes, void* data)
   {
      return fread(data, 1, numBytes, mFP);
   }
   
   virtual unsigned int write(int numBytes, void* data)
   {
      return fwrite(data, 1, numBytes, mFP);
   }
   
   virtual void setStreamPos(unsigned int pos)
   {
      fseek(mFP, pos, SEEK_SET);
   }
   
   virtual void advanceStreamPos(unsigned int pos)
   {
      fseek(mFP, pos, SEEK_CUR);
   }
   
   virtual unsigned int getStreamPos()
   {
      return ftell(mFP);
   }
   
   virtual unsigned int getStreamSize()
   {
      int pos = ftell(mFP);
      fseek(mFP, 0, SEEK_END);
      int end = ftell(mFP);
      fseek(mFP, pos, SEEK_SET);
      return end;
   }
   
   virtual bool isEOF()
   {
      return feof(mFP);
   }
   
protected:
   
   FILE *mFP;
};

class TexFile
{
public:
   TexFile() : mData(0)
   {
      
   }
   
   ~TexFile()
   {
      if (mData)
      {
         free(mData);
         mData = NULL;
      }
   }
   
   TexHeaderStruct mHeader;
   unsigned char *mData;
   unsigned int mStreamSize;
   
   bool read(Stream *stream)
   {
      if (stream->read(sizeof(TexHeaderStruct), &mHeader) < sizeof(TexHeaderStruct))
         return false;
      
      if (mHeader.magic != 542655828)
      {
         printf("Invalid header\n");
         return false;
      }
      
      if (mHeader.version != 7)
      {
         printf("Invalid version %u\n", mHeader.version);
         return false;
      }
      
      unsigned int size = stream->getStreamSize() - sizeof(TexHeaderStruct);
      mData = (unsigned char*)malloc(size);
      mStreamSize = stream->read(size, mData);
      
      return true;
   }
   
   bool write(Stream *stream)
   {
      return false;
   }
};




void fix_path(char *path)
{
   int len = strlen(path);
   for (int i=0; i<len; i++)
   {
      if (path[i] == '/' || path[i] == '\\')
         path[i] = '/';
   }
}

bool folder_exists(const char *path)
{
   // Sanitize path
   char folderpath[4096];
   strncpy(folderpath, path, sizeof(folderpath));
   folderpath[sizeof(folderpath)-1] = '\0';
   fix_path(folderpath);
   
   struct stat fStat;
   if (stat(folderpath, &fStat) < 0)
      return false;
   
   // if the file is a Directory then true
   if ( (fStat.st_mode & S_IFMT) == S_IFDIR)
      return true;
   
   return false;
}

bool create_folder(const char *path)
{
   // Sanitize path
   char folderpath[4096];
   char folderbuf[4096];
   strncpy(folderpath, path, sizeof(folderpath));
   folderpath[sizeof(folderpath)-1] = '\0';
   fix_path(folderpath);
   folderbuf[0] = '\0';
   
   // Iterate and create
   const char *ptr = folderpath;
   unsigned int pathItr = 0;
   while((ptr = strchr(ptr, '/')) != NULL)
   {
      if (ptr - folderpath > 0)
      {
         strncpy(folderbuf, folderpath, ptr - folderpath);
         folderbuf[(ptr-folderpath)] = 0;
      }
      
      if (strlen(folderbuf) > 0 && !folder_exists(folderbuf))
      {
         if (mkdir(folderbuf, 0700) != 0)
            return false;
      }
      
      ptr++;
   }
   
   // Sort out final /
   if (strlen(path) > 0 && !folder_exists(path))
   {
      if (mkdir(path, 0700) != 0)
         return false;
   }
   
   return true;
}

int dump_tex(int argc, const char * argv[])
{
   TexFile tex;
   FileStream inStream;
   FileStream outStream;
   
   if (!inStream.open(argv[0], "rb"))
   {
      printf("Error input file %s\n", argv[0]);
      return 1;
   }
   
  /* if (!outStream.open(argv[1], "wb"))
   {
      printf("Error output file %s\n", argv[1]);
      return 1;
   }*/
   
   if (!tex.read(&inStream))
   {
      printf("Error input file %s\n", argv[0]);
      return 1;
   }
   
   // Dump the raw rgb
   unsigned int size = tex.mHeader.size * tex.mHeader.size * 4;
   unsigned char *outputData = (unsigned char *)malloc(size);
   
   int result = 0;
   int actualSize = 0;
   const char *fmt = "UNKN";
   bool hasMips = tex.mHeader.flags & 0x20;
   
   if (tex.mHeader.unknown0[1] == 11 || tex.mHeader.unknown0[1] == 13) // PVRTC
   {
      unsigned int bytes = PVRTDecompressPVRTC(tex.mData, 0, tex.mHeader.size, tex.mHeader.size, outputData);
      result = stbi_write_tga(argv[1], tex.mHeader.size, tex.mHeader.size, STBI_rgb_alpha, outputData);
      fmt = "PVRTC";
      actualSize = ( std::max((int)tex.mHeader.size, 8) * std::max((int)tex.mHeader.size, 8) * 4 + 7) / 8;
   }
   else if (tex.mHeader.unknown0[1] == 1) // RGBA
   {
      memcpy(outputData, tex.mData, tex.mHeader.size*tex.mHeader.size*4);
      //result = stbi_write_tga(argv[1], tex.mHeader.size, tex.mHeader.size, STBI_rgb_alpha, outputData);
      fmt = "RGBA";
      actualSize =  tex.mHeader.size*tex.mHeader.size*4;
   }
   else if (tex.mHeader.unknown0[1] == 0) // RGB
   {
      memcpy(outputData, tex.mData, tex.mHeader.size*tex.mHeader.size*3);
      //result = stbi_write_tga(argv[1], tex.mHeader.size, tex.mHeader.size, STBI_rgb, outputData);
      fmt = "RGB ";
      actualSize =  tex.mHeader.size*tex.mHeader.size*3;
   }
   else if (tex.mHeader.unknown0[1] == 6) // RGBA5551
   {
      unsigned short *in = (unsigned short*)tex.mData;
      unsigned char *out = outputData;
      for (int i=0; i<tex.mHeader.size*tex.mHeader.size; i++)
      {
         
         unsigned short alpha_mask = 0x800;
         unsigned short red_mask = 0x7C00;
         unsigned short green_mask = 0x3E0;
         unsigned short blue_mask = 0x1F;
         
         unsigned short inv = *in;
         inv >>= 1;
         
         *out++  = (inv & blue_mask) << 3;
         *out++  = ((inv & green_mask) >> 5) << 3;
         *out++  = ((inv & red_mask) >> 10) << 3;
         *out++  = (*in & 0x1) ? 255 : 0;
         in++;
      }
      //result = stbi_write_tga(argv[1], tex.mHeader.size, tex.mHeader.size, STBI_rgb_alpha, outputData);
      fmt = "5551";
      actualSize =  tex.mHeader.size*tex.mHeader.size*2;
   }
   else if (tex.mHeader.unknown0[1] == 7) // LUMA
   {
      memcpy(outputData, tex.mData, tex.mHeader.size*tex.mHeader.size*4);
      //result = stbi_write_tga(argv[1], tex.mHeader.size, tex.mHeader.size, STBI_grey_alpha, outputData);
      fmt = "LUMA";
      actualSize =  tex.mHeader.size*tex.mHeader.size*2;
   }
   else
   {
      printf("WARNING! UNKNOWN FORMAT %i!\n", tex.mHeader.unknown0[2]);
      
      memcpy(outputData, tex.mData, tex.mHeader.size*tex.mHeader.size*4);
      //result = stbi_write_tga(argv[1], tex.mHeader.size, tex.mHeader.size, STBI_rgb_alpha, outputData);
      actualSize =  tex.mHeader.size*tex.mHeader.size*4;
   }
   
   if (tex.mHeader.unknown4[1] != 45 && tex.mHeader.unknown4[2] != 49 && tex.mHeader.unknown4[2] != 49)
   {
      printf("WEIRD FILE\n");
   }
   
   printf("HEADER:\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%i\t%u\t%u\t%s\t%s\n", tex.mHeader.unknown0[0], tex.mHeader.unknown0[1], tex.mHeader.unknown0[2], tex.mHeader.unknown4[0], tex.mHeader.unknown4[1], tex.mHeader.unknown4[2], tex.mHeader.unknown4[3], tex.mHeader.unknown8, tex.mHeader.flags, tex.mHeader.size, fmt, argv[0]);
   
   if (actualSize < tex.mStreamSize)
   {
      if (hasMips)
      {
         printf("^^Might have mips. FLAGGED. Extra %i bytes\n", tex.mStreamSize - actualSize);
      }
      else
      {
         printf("^^Might have mips. NO FLAG. Extra %i bytes\n", tex.mStreamSize - actualSize);
      }
   }
   else if (hasMips)
   {
      printf("^^Mips flag but no extra bytes!\n");
   }
   
   //unsigned int bytes = PVRTDecompressPVRTC(tex.mData, 0, tex.mHeader.size, tex.mHeader.size, outputData);
   //memcpy(outputData, tex.mData, tex.mHeader.size*tex.mHeader.size*4);
   //int result = stbi_write_tga(argv[1], tex.mHeader.size, tex.mHeader.size, STBI_rgb_alpha, outputData);
   
   free(outputData);
   
   if (result < 1)
   {
      printf("Error output file %s\n", argv[1]);
      return 1;
   }
   
   return 0;
}

int main(int argc, const char * argv[])
{
   if (argc < 3)
   {
      printUsage();
      return 1;
   }
   
   const char *mode = argv[1];
   
   switch(*mode)
   {
      case 'd':
         return dump_tex(argc-2, argv+2);
         break;
         
      default:
         printUsage();
         return 1;
         
   }
   return 0;
}

