// code adapted from Jonathan Levin's http://www.newosxbook.com/src.jl?tree=listings&file=6-bonus.c
// clean-up a bit to
// 1. make "clang -Wall" happy
// 2. remove img3 stuff: device tree files are in im4p nowadays

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "dt.h"		   // for DeviceTree

int verbose = 0;

void copyValue (char *dest, char *src, int length)
{
    int i = 0;
    for (i = 0; src[i] || i < length; i++);

    if (i != length) {
        strcpy(dest, "(null)");
        return;
    }
    memcpy(dest, src, length);
}

uint32_t dumpTreeNode(DeviceTreeNode *Node, int indent)
{
    char buffer[81920];
    char temp[10240];
    char h_temp[49152];
    char *name;

    int prop = 0, child = 0;
    int i = 0;
    memset(buffer, '\0', 4096);

    DeviceTreeNodeProperty *dtp = (DeviceTreeNodeProperty * ) ((char*)Node + sizeof(DeviceTreeNode));

    char *offset = 0;
    int real_len;
    for (prop = 0; prop < Node->nProperties; prop++) {
        real_len = dtp->length;
        temp[0] = '\0'; // strcat will do the rest
        for (i=0; i< indent ; i++) {
            strcat(temp,"|  ");
        }
        strcat(temp, "+--");
        strncat(buffer, temp, 1024);
        if ((real_len & 0x80000000) > 0)
            real_len = real_len - 0x80000000;
        sprintf(temp, "%s %d bytes: ", dtp->name, real_len);
        strncat(buffer, temp, 1024);

        if (strcmp(dtp->name,"name") == 0) {
            name = (char *) &dtp->length + sizeof(uint32_t);
            strncat(buffer, name, dtp->length);
            strcat(buffer,"\n");
        } else {
            copyValue(temp, ((char *) &dtp->length) + sizeof(uint32_t), real_len);
            // Yeah, Yeah, Buffer overflows, etc.. :-)
            if (verbose) {
                char *hex = h_temp;
                for (i=0; i < real_len; i++) {
                    sprintf(hex, " 0x%02x", 0xff & *(((char *) &dtp->length) + sizeof(uint32_t) + i));
                    hex += 5; // len(" 0x??") = 5
                }
            }

            strcat(buffer, temp);
            if (verbose)
                strcat(buffer, h_temp);
            strcat(buffer, "\n");
        }
        dtp = (DeviceTreeNodeProperty *) (((char *) dtp) + sizeof(DeviceTreeNodeProperty) + real_len);

        // Align
        dtp =  (((long)dtp % 4) ? (DeviceTreeNodeProperty *) (((char *) dtp)  + (4 - (((long)dtp) % 4))) : dtp);
        offset = (char *) dtp;
    }

    for (i=0; i < indent-1; i++) {
        printf("   ");
    }

    if (indent > 1)
        printf ("+--");
    printf("%s:\n", name);
    printf("%s", buffer);

    // Now do children:
    for (child = 0; child < Node->nChildren; child++) {
        offset+= dumpTreeNode((DeviceTreeNode *) offset, indent+1);
    }

    return ( (char *) offset - (char*) Node);
}

void decrypt(uint8_t* ciphertext, uint32_t length, uint8_t* key,
             uint8_t* iv, uint8_t* plaintext)
{
    uint32_t len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, length);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
}

int
main(int argc, char **argv)
{
    char *filename;
    int rc;
    int fd;
    int filesize;
    uint8_t mmapped[0x40000];

    if (argc < 2) {
        fprintf (stderr,"Usage: %s [-v] _filename_\n", argv[0]);
        exit(0);
    }

    if (strcmp(argv[1], "-v") == 0)
        verbose = 1;

    filename = argv[argc -1];

    FILE* fp = fopen(filename, "rb");
    if(!fp) return 1;

    int img2 = 0;

    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char magic8900[4];
    magic8900[0] = fgetc(fp);
    magic8900[1] = fgetc(fp);
    magic8900[2] = fgetc(fp);
    magic8900[3] = fgetc(fp);
    if(magic8900[0] == '8' && magic8900[1] == '9' && magic8900[2] == '0' && magic8900[3] == '0')
    {
        fseek(fp, 0x7fc, SEEK_CUR);
        filesize -= 0x800;
        char magicimg2[4];
        magicimg2[0] = fgetc(fp);
        magicimg2[1] = fgetc(fp);
        magicimg2[2] = fgetc(fp);
        magicimg2[3] = fgetc(fp);
        if(magicimg2[0] == '2' && magicimg2[1] == 'g' && magicimg2[2] == 'm' && magicimg2[3] == 'I')
        {
            fseek(fp, 0x3fc, SEEK_CUR);
            filesize -= 0x400;
            img2 = 1;
        }
    }

    int img3 = 0;

    if(!img2)
    {
        fseek(fp, 0, SEEK_SET);
        uint32_t addr = 0;

        char magicimg3[4];
        magicimg3[0] = fgetc(fp);
        magicimg3[1] = fgetc(fp);
        magicimg3[2] = fgetc(fp);
        magicimg3[3] = fgetc(fp);
        if(magicimg3[0] == '3' && magicimg3[1] == 'g' && magicimg3[2] == 'm' && magicimg3[3] == 'I')
        {
            printf("IMG3 DOES NOT WORK YET DUE TO BAD KEYS, DO NOT USE\n");
            img3 = 0;
            //img3 = 1;
            addr += 0x4;
            fseek(fp, 0x10, SEEK_CUR);
            filesize -= 0x14;
            addr += 0x10;
            uint8_t encrypted[0x40000];
            char magicimg3tag[4];
            int done = 0;
            while(!done)
            {
                magicimg3tag[0] = fgetc(fp);
                magicimg3tag[1] = fgetc(fp);
                magicimg3tag[2] = fgetc(fp);
                magicimg3tag[3] = fgetc(fp);
                addr += 0x4;
                if(magicimg3tag[0] == 'A' && magicimg3tag[1] == 'T' && magicimg3tag[2] == 'A' && magicimg3tag[3] == 'D')
                {
                    uint32_t datalength;
                    fseek(fp, 0x4, SEEK_CUR);
                    addr += 0x4;
                    fread(&datalength, 1, 4, fp);
                    addr += 0x4;
                    filesize = datalength;
                    uint32_t encryptioncheck;
                    fread(&encryptioncheck, 1, 4, fp);
                    if(encryptioncheck > 0x100) done = 0;
                    else done = 1;

                    fseek(fp, -4, SEEK_CUR);

                    fread(encrypted, 1, filesize, fp);
                    addr += filesize;
                }
                else if(magicimg3tag[0] == 'G' && magicimg3tag[1] == 'A' && magicimg3tag[2] == 'B' && magicimg3tag[3] == 'K')
                {
                    uint32_t aestype;
                    fseek(fp, 0xc, SEEK_CUR);
                    addr += 0xc;
                    fread(&aestype, 1, 4, fp);
                    addr += 0x4;
                    uint32_t enciv[4];
                    fread(enciv, 1, 16, fp);
                    addr += 0x10;
                    uint32_t enckey[4];
                    fread(enckey, 1, 16, fp);
                    addr += 0x10;
                    uint32_t iv[4];
                    uint32_t key[4];
                    if(enciv[0] == 0xA95BD15F && enciv[1] == 0xC45265AB && enciv[2] == 0x86896139 && enciv[3] == 0xFC629C5D)
                    {
                        iv[0] = 0x6730d375;
                        iv[1] = 0xacdf168e;
                        iv[2] = 0x3bc2f722;
                        iv[3] = 0xad41f2ba;
                        key[0] = 0x6d257c6a;
                        key[1] = 0x3f82665a;
                        key[2] = 0x48939044;
                        key[3] = 0x462631c8;
                    }

                    decrypt(encrypted, filesize, (uint8_t*)key, (uint8_t*)iv, mmapped);

                    done = 1;
                }
                else
                {
                    uint32_t totallength;
                    fread(&totallength, 1, 4, fp);
                    addr += 0x4;
                    fseek(fp, totallength - 8, SEEK_CUR);
                    addr += totallength - 8;
                }
            }
        }
    }
    if(!img3)
    {
        if(fread(mmapped, 1, filesize, fp) != filesize) return 3;
    }

    char *data = mmapped;
    DeviceTreeNode *dtn = (DeviceTreeNode *) data;
    printf ("\tDevice Tree with %d properties and %d children\n", dtn->nProperties, dtn->nChildren);

    printf("Properties:\n");
    dumpTreeNode (dtn,1);

    return 0;
}

