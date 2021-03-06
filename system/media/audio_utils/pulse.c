/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
**
** Copyright 2012, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/



/* #define LOG_NDEBUG 0 */
#define LOG_TAG "audio_utils_pulse"

#include <stdio.h>
#include <stdlib.h>
#include <cutils/log.h>
#include <audio_utils/format.h>
#include <audio_utils/pulse.h>


#ifdef MTK_LATENCY_DETECT_PULSE

#define MAX_FRAMECOUNT  1024
#define MAX_CHANNEL     2


static char *TagString[] = {
    "CAPTURE_DATA_PROVIDER",
    "CAPTURE",
    "AUDIO_RECORD",
    "AUDIO_TRACK",
    "MIXER",
    "PLAYERBACK_HANDLER",
    "CAPTURE_DATA_CLIENT", "UNKNOW"
};


static void dumpPCMData(const char * filepath, void * buffer, int count)
{
   FILE * fp= fopen(filepath, "ab+");
   if(fp!=NULL)
   {
        fwrite(buffer,1,count,fp);
        fclose(fp);
   }
   else
   {
        ALOGE("open file fail");
   }
}

const char* Tag2String(const int TagNum)
{
    return TagString[TagNum];
}

void detectPulse_(const int TagNum, const int pulseLevel, short* ptr, const size_t desiredFrames, const int channels)
{
    static const int duration = 1024;
    static int       keepCount[30] = {0};
    static int       keepCountAll[30] = {0};

    if (ptr == NULL || desiredFrames <= 0)
        return ;

    //ALOGD("%s, keepCountAll %d, keepCount %d", __FUNCTION__, keepCountAll[TagNum], keepCount[TagNum]);

    int *pKeepCount = &keepCount[TagNum];
    int tempCount, i, j;
    for(i=0, j=0, tempCount=0; i<(int)desiredFrames; i++)
    {
        if(ptr[i*channels] >= pulseLevel)
        {
            //ALOGD("pulseLevel %d, ptr 0x%x, keepCount %d, duration %d\n", pulseLevel, ptr[i<<1], keepCount, duration);
            if((*pKeepCount) && (*pKeepCount) < duration)     // length of pulse required exceeds duration
            {
                (*pKeepCount) += i-j;
                tempCount += i-j;
                j=i;
                continue;
            }

            ALOGD("TagNum %d - %s, detect Pulse, keepCountAll %d, pulseLevel %d", TagNum, Tag2String(TagNum),
                                                                            keepCountAll[TagNum]+i, pulseLevel);
            (*pKeepCount) = desiredFrames - i;    // first time more than the threshold
            break;
        }
    }

    // sum abs
    int k, sum=0;
    for(k=0; k<(int)desiredFrames; k++) {
        sum += abs((int)ptr[k*channels]);
    }
    ALOGD("TagNum %d - %s, sum %d", TagNum, Tag2String(TagNum), sum);

    if(i==(int)desiredFrames && (*pKeepCount))
    {
        (*pKeepCount) += desiredFrames - tempCount;
    }

    keepCountAll[TagNum] += desiredFrames;
}

 void detectPulse(const int TagNum, const int pulseLevel, const int dump, void* ptr,
                  const size_t desiredFrames, const audio_format_t format,
                  const int channels,  __attribute__((unused)) const int sampleRate)
{
    //ALOGD("%s, TagNum %d, pulseLevel %d, format %d, frames %d, channels %d",
    //            __FUNCTION__, TagNum, pulseLevel, format, (int)desiredFrames, channels);

    if(TagNum >= TAG_MAX) {
        ALOGE("%s, TagNum %d is not support!!", __FUNCTION__, TagNum);
        return;
    }
    if(!format&AUDIO_FORMAT_PCM_16_BIT && !format&AUDIO_FORMAT_PCM_32_BIT && !format&AUDIO_FORMAT_PCM_FLOAT) {
        ALOGE("%s, TagNum %d, format(%d) is not support!!", __FUNCTION__, TagNum, format);
        return;
    }
    if(channels > MAX_CHANNEL) {
        ALOGE("%s, TagNum %d, channel(%d) is not support!!", __FUNCTION__, TagNum, channels);
        return;
    }
    if(desiredFrames > MAX_FRAMECOUNT) {
        ALOGE("%s, TagNum %d, frames(%d) is not support!!", __FUNCTION__, TagNum, (int)desiredFrames);
        return;
    }


    char  fileName[80] = {0};
    short buffer[MAX_FRAMECOUNT*MAX_CHANNEL];

/*
    if(dump) {
        // dump pcm
        sprintf(fileName, "%s.%d.pcm", "/sdcard/mtklog/audio_dump/detectPulse_Original_Tag", TagNum);
        dumpPCMData(fileName, ptr, desiredFrames*channels *audio_bytes_per_sample(format));
    }
*/
    memcpy_by_audio_format(buffer, AUDIO_FORMAT_PCM_16_BIT, ptr, format, desiredFrames * channels);

    if(dump) {
        // dump pcm
        sprintf(fileName, "%s.%d.pcm", "/sdcard/mtklog/audio_dump/detectPulse_16bit_Tag", TagNum);
        dumpPCMData(fileName, buffer, desiredFrames*channels *audio_bytes_per_sample(AUDIO_FORMAT_PCM_16_BIT));
    }

    detectPulse_(TagNum, pulseLevel, (short *)buffer, desiredFrames, channels);
}

#else

void detectPulse(const int TagNum __unused, const int pulseLevel __unused, const int dump __unused, void* ptr __unused,
                 const size_t desiredFrames __unused, const audio_format_t format __unused,
                 const int channels __unused, const int sampleRate __unused)
{
}

#endif

