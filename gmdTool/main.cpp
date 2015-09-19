#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <vector>
#include <string>
#include <unordered_map>

#include <sys/stat.h>
#include <unistd.h>

void printUsage()
{
   printf("gmdTool\nUsage:\n\\gmdTool c/d infile outfile\n");
}

#pragma pack(1)
typedef struct GMDHeaderStruct
{
   unsigned int magic;
   unsigned int magic2; // 01 02 01 00
} GMDHeaderStruct;
#pragma pack()

#pragma pack(1)
typedef struct GMDKey
{
   unsigned int index;
   unsigned int keyPtr;
} GMDKey;
#pragma pack(0)

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

class GMDFile
{
public:
   GMDFile() : mName(0)
   {
      
   }
   
   ~GMDFile()
   {
      if (mName)
      {
         free(mName);
         mName = NULL;
      }
      
      for (int i=0; i<mValueList.size(); i++)
      {
         delete mValueList[i];
      }
   }
   
   // Internal representation of GMDKey for editing
   typedef struct GMDKeyEntry
   {
      unsigned int index;
      std::string value;
   } GMDKeyEntry;
   
   GMDHeaderStruct mHeader;
   char *mName;
   
   std::vector<GMDKeyEntry> mKeyList;
   std::vector<std::string*> mValueList;
   
   bool read(Stream *stream)
   {
      if (stream->read(sizeof(GMDHeaderStruct), &mHeader) < sizeof(GMDHeaderStruct))
         return false;
      
      if (mHeader.magic != 4476231)
      {
         printf("Invalid header magic1\n");
         return false;
      }
      
      if (mHeader.magic2 != 0x00010201)
      {
         printf("Invalid header magic2\n");
         return false;
      }
      
      unsigned int lang = 0;
      unsigned int buffer[2];
      
      stream->read(sizeof(unsigned int), &lang);
      stream->read(sizeof(buffer), &buffer);
      
      if (lang != 1)
      {
         printf("Unusual header %u\n", lang);
         //return false;
      }
      
      // Following variable fields...
      unsigned int numKeys;
      unsigned int numValues;
      unsigned int keyLength;
      unsigned int valueLength;
      unsigned int nameLength;
      
      stream->read(sizeof(unsigned int), &numKeys);
      stream->read(sizeof(unsigned int), &numValues);
      stream->read(sizeof(unsigned int), &keyLength);
      stream->read(sizeof(unsigned int), &valueLength);
      stream->read(sizeof(unsigned int), &nameLength);
      
      mName = (char*)malloc(nameLength+1);
      stream->read(nameLength+1, mName);
      mName[nameLength] = '\0';
      
      mKeyList.resize(numKeys);
      mValueList.resize(numValues);
      
      // Read key map
      GMDKey *keymapData = (GMDKey*)malloc(numKeys * sizeof(GMDKey));
      stream->read(numKeys * sizeof(GMDKey), keymapData);
      
      // Read keys
      char *stringData = (char*)malloc(keyLength);
      char *ptr = stringData;
      stream->read(keyLength, stringData);
      for (int i=0; i<numKeys; i++)
      {
         mKeyList[i].index = keymapData[i].index;
         mKeyList[i].value = ptr;
         ptr += strlen(ptr) + 1;
      }
      
      free(stringData);
      
      
      // Read values
      stringData = (char*)malloc(valueLength);
      ptr = stringData;
      stream->read(valueLength, stringData);
      for (int i=0; i<numValues; i++)
      {
         mValueList[i] = new std::string(ptr);
         ptr += strlen(ptr) + 1;
      }
      
      free(stringData);
      
      
      // Cleanup
      free(keymapData);
      
      
      return true;
   }
   
   bool write(Stream *stream)
   {
      mHeader.magic = 4476231;
      mHeader.magic2 = 0x00010201;
      stream->write(sizeof(GMDHeaderStruct), &mHeader);
      
      
      unsigned int numKeys = mKeyList.size();
      unsigned int numValues = mValueList.size();
      unsigned int keyLength = 0;
      unsigned int valueLength = 0;
      unsigned int count = 1;
      unsigned int nameLength = strlen(mName);
      
      int buffer[2];
      memset(buffer, '\0', sizeof(buffer));
      stream->write(sizeof(unsigned int), &count);
      stream->write(sizeof(buffer), &buffer);
      
      // Determine total length of keys and values
      for (int i=0; i<mKeyList.size(); i++)
      {
         keyLength += strlen(mKeyList[i].value.c_str()) + 1;
      }
      for (int i=0; i<mValueList.size(); i++)
      {
         valueLength += strlen(mValueList[i]->c_str()) + 1;
      }
      
      // Construct key and value list
      
      GMDKey *keyMap = (GMDKey*)malloc(numKeys * sizeof(GMDKey));
      char *keyList = (char*)malloc(keyLength);
      char *valueList = (char*)malloc(valueLength);
      
      char *ptr = keyList;
      for (int i=0; i<mKeyList.size(); i++)
      {
         strcpy(ptr, mKeyList[i].value.c_str());
         keyMap[i].index = mKeyList[i].index;
         keyMap[i].keyPtr = 1224944080 + (unsigned int)(ptr - keyList);
         ptr += strlen(ptr) + 1;
      }
      ptr = valueList;
      for (int i=0; i<mValueList.size(); i++)
      {
         //printf("%s\n!!!!!!", mValueList[i]->c_str());
         strcpy(ptr, mValueList[i]->c_str());
         ptr += strlen(ptr) + 1;
      }
      
      stream->write(sizeof(unsigned int), &numKeys);
      stream->write(sizeof(unsigned int), &numValues);
      stream->write(sizeof(unsigned int), &keyLength);
      stream->write(sizeof(unsigned int), &valueLength);
      stream->write(sizeof(unsigned int), &nameLength);
      stream->write(nameLength+1, mName);
      
      stream->write(numKeys * sizeof(GMDKey), keyMap);
      stream->write(keyLength, keyList);
      stream->write(valueLength, valueList);
      
      free(keyMap);
      free(keyList);
      free(valueList);
         
      return true;
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

int dump_gmd(int argc, const char * argv[])
{
   GMDFile gmd;
   FileStream inStream;
   FileStream outStream;
   
   if (!inStream.open(argv[0], "rb"))
   {
      printf("Error input file %s\n", argv[0]);
      return 1;
   }
   
   if (!outStream.open(argv[1], "wb"))
   {
      printf("Error output file %s\n", argv[1]);
      return 1;
   }
   
   if (!gmd.read(&inStream))
   {
      printf("Error input file %s\n", argv[0]);
      return 1;
   }
   
   // Print to output
   char buffer[1024*16];
   snprintf(buffer, sizeof(buffer), "%s\n[@keys]\n", gmd.mName);
   outStream.write(strlen(buffer), buffer);
   for (int i=0; i<gmd.mKeyList.size(); i++)
   {
      snprintf(buffer, sizeof(buffer), "%s=%i\n", gmd.mKeyList[i].value.c_str(), gmd.mKeyList[i].index);
      outStream.write(strlen(buffer), buffer);
   }
   for (int i=0; i<gmd.mValueList.size(); i++)
   {
      snprintf(buffer, sizeof(buffer), "[@value.%i]\n%s\n", i, gmd.mValueList[i]->c_str());
      outStream.write(strlen(buffer), buffer);
   }
   
   return 0;
}

char* read_keys(GMDFile &gmd, char *ptr, char *end)
{
   // key=value\n
   char *startLine = ptr;
   char *startValue = ptr;
   char *itr = ptr;
   std::string key = "";
   
   while (itr < end && !(*itr == '[' && *(itr+1) == '@'))
   {
      if (*itr == '=')
      {
         GMDFile::GMDKeyEntry entry;
         
         *itr = '\0';
         key = startLine;
         startValue = itr+1;
         while (itr < end && !(*itr == '[' && *(itr+1) == '@'))
         {
            if (*itr == '\r' || *itr == '\n')
            {
               if (*itr == '\n')
               {
                  startLine = itr+1;
               }
               
               // End of number
               *itr = '\0';
               entry.value = key;
               entry.index = atoi(startValue);
               break;
            }
            else
            {
               itr++;
            }
         }
         
         gmd.mKeyList.push_back(entry);
      }
      else if (*itr == '\n')
      {
         startLine = itr+1;
      }
      itr++;
   }
   
   return itr;
}

char* read_value(GMDFile &gmd, char *ptr, char *end, int valueIndex)
{
   // data
   char *itr = ptr;
   while (itr < end && !(*itr == '[' && *(itr+1) == '@'))
   {
      itr++;
   }
   
   // Copy from ptr...itr, excluding last newline
   if (*(itr-1) == '\n') *(itr-1) = '\0';
   *itr = '\0';
   gmd.mValueList[valueIndex] = new std::string(ptr);
   if (itr < end) *itr = '[';
   return itr;
}

int create_gmd(int argc, const char * argv[])
{
   GMDFile gmd;
   FileStream inStream;
   FileStream outStream;
   
   if (!inStream.open(argv[0], "rb"))
   {
      printf("Error input file %s\n", argv[0]);
      return 1;
   }
   
   if (!outStream.open(argv[1], "wb"))
   {
      printf("Error output file %s\n", argv[1]);
      return 1;
   }
   
   // TODO: process inStream to gmd
   unsigned int inBytes = inStream.getStreamSize()+1;
   char *inData = (char*)malloc(inBytes);
   inBytes = inStream.read(inBytes, inData);
   
   char *ptr = inData;
   char *sptr = inData;
   char *end = inData + inBytes;
   *end = '\0';
   std::string inKey = "";
   std::string inValue = "";
   
   // Read name
   
   while (ptr < end)
   {
      if (*ptr == '\r')
         *ptr = '\0';
      
      // EOL
      if (*ptr == '\n')
      {
         *ptr = '\0';
         if (gmd.mName)
            free(gmd.mName);
         gmd.mName = (char*)malloc(strlen(inData)+1 );
         strcpy(gmd.mName, inData);
         ptr++;
         break;
      }
      
      ptr++;
   }
   
   
   // Read in sections
   
   while (ptr < end)
   {
      char c = *ptr++;
      if (c == '[' && *ptr == '@')
      {
         // Search for end
         sptr = ptr;
         while (sptr < end)
         {
            if (*sptr == '\]')
            {
               *sptr = '\0';
               inKey = ptr;
               
               // Skip newline
               while (sptr < end && (*sptr != '\n')) sptr++;
               sptr++;
               ptr = sptr;
               
               // Determine key
               if (strcmp(inKey.c_str(), "@keys") == 0)
               {
                  ptr = sptr = read_keys(gmd, ptr, end);
               }
               else if (strncmp(inKey.c_str(), "@value", 6) == 0)
               {
                  if (ptr+2 >= end)
                     break;
                  
                  // Determine value index
                  const char *scanDot = inKey.c_str();
                  const char *dot = strrchr(scanDot, '.');
                  if (dot != NULL)
                  {
                     int index = atoi(dot+1);
                     if (index >= 0)
                     {
                        // Make sure value exists at index
                        while (gmd.mValueList.size() <= index)
                        {
                           gmd.mValueList.push_back(NULL);
                        }
                        
                        // Read value
                        ptr = sptr = read_value(gmd, sptr, end, index);
                     }
                  }
               }
               
               break;
            }
            else
            {
               sptr++;
            }
         }
         
         ptr = sptr;
      }
   }
   
   free(inData);
   
   if (!gmd.write(&outStream))
   {
      printf("Error input file %s\n", argv[0]);
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
         return dump_gmd(argc-2, argv+2);
         break;
         
      case 'c':
         return create_gmd(argc-2, argv+2);
         break;
         
      default:
         printUsage();
         return 1;
         
   }
   return 0;
}

