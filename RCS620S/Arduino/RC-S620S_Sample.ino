/*
 *
 * RC-S620/S 用サンプルプログラム
 *
 *  - ターゲットが ISO/IEC 14443 Type A (MIFARE) の場合
 *      ID を取得しシリアルへ出力
 *          - MIFARE Ultralight の場合
 *              メモリ内容のダンプをシリアルへ出力
 *                  - NDEF メッセージが記録されている場合
 *                      NDEF レコード内容を順次取得しシリアルへ出力 
 *
 *  - ターゲットが ISO/IEC 14443 Type B の場合
 *      擬似 ID である PUPI (Pseudo-Unique PICC Identifier) を取得しシリアルへ出力 
 *
 *  - ターゲットが FeliCa (Standard / Lite / Lite-S) の場合
 *      IDm を取得しシリアルへ出力 
 *
 *  Copyright 2018 KLab Inc.
 *
 */

#include <RCS620S.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <SoftwareSerial.h>

#define POLLING_INTERVAL 1000
#define LED_PIN 13

RCS620S rcs620s;
SoftwareSerial softwareSerial(10, 11); // RX, TX

void dbg(const char *format, ...);
void dump(uint8_t* buf, uint8_t len, char *sep=" ", char *term="\r\n");
bool waitForTypeA(int count);
void dumpMifareUL(uint8_t totalPage);
bool showMifareULNdefMessage();

void setup()
{
  int ret;
  pinMode(LED_PIN, OUTPUT);

  Serial.begin(115200);
  softwareSerial.begin(115200);

  dbg("wait for initDevice..");
  while (1) {
    if (rcs620s.initDevice()) {
      dbg("done\r\n");
      break;
    }
  }
  dbg("waiting for card..\r\n");
}

void loop()
{
  uint8_t size, type = PICC_UNKNOWN;
  uint8_t buf[20];
  bool found = false;
  
  digitalWrite(LED_PIN, LOW);

  if (rcs620s.polling() ||
      rcs620s.polling_typeA() ||
      rcs620s.polling_typeB()) {
    digitalWrite(LED_PIN, HIGH);
    dbg("ID: ");
    for (int i = 0; i < rcs620s.idLength; i++) {
      dbg("%02X ", rcs620s.idm[i]);
    }
    type = rcs620s.piccType;
    if (type == PICC_ISO_IEC14443_TypeA_MIFARE) {
        dbg("(ISO/IEC14443 Type A MIFARE)\r\n");                
    } else if (type == PICC_ISO_IEC14443_TypeA_MIFAREUL) {
        dbg("(ISO/IEC14443 Type A MIFARE Ultralight)\r\n");                
    } else if (type == PICC_ISO_IEC14443_TypeB) {
        dbg("(ISO/IEC14443 Type B)\r\n");
    } else if (type == PICC_FELICA) {
        dbg("(FeliCa)\r\n");
    } else {
        dbg("(Unknown PICC Type)\r\n");                
    }
  }
  switch (type) {
    case PICC_ISO_IEC14443_TypeA_MIFAREUL:
      size = sizeof(buf);
      uint8_t totalPages = rcs620s.getTotalPagesMifareUL();
      if (totalPages == 0) { // ! NTAG21x
        totalPages = 0xff;
      }
      if (waitForTypeA(10)) {  // 再捕捉
        dumpMifareUL(totalPages);
      }
      if (waitForTypeA(10)) {
        showMifareULNdefMessage();
      }
      break;
  }
  if (type != PICC_UNKNOWN) {
    dbg("\r\nwaiting for card..\r\n");
  }
  delay(POLLING_INTERVAL);
}

void dbg(const char *format, ...) {
  char b[64];
  va_list va;
  va_start(va, format);
  vsnprintf(b, sizeof(b), format, va);
  va_end(va);
  softwareSerial.print(b);
}

void dump(uint8_t *array, uint8_t len, char *sep, char *term) {
  for (uint8_t i = 0; i < len; i++) {
      dbg("%02X%s", array[i], (sep != NULL && i < len-1) ? sep : "");
  }
  dbg("%s", (term != NULL) ? term : "");
}

// MIFARE 近接待機
bool waitForTypeA(int count) {
  for (int i = 0; i < count; i++) {
    if (rcs620s.polling_typeA()) {
      return true;
    }
    delay(50);
  }
  return false;
}

// MIFARE Ultralight のメモリページをダンプ
void dumpMifareUL(uint8_t totalPages) {
  uint8_t buf[20];
  for (uint8_t page = 0; page < totalPages; page+=4) {
    uint8_t len = sizeof(buf);
    uint8_t sts = rcs620s.readMifareUL(page, buf, &len);
    if (!sts) {
        break;
    }
    for (int i = 0; i < len; i++) {
      if (i % 4 == 0) {
        int curPage = page + i / 4;
        if (curPage >= totalPages) {
            break;
        }
        dbg(" [%03X] ", curPage);   
      }
      dbg("%02X ", buf[i]);
      if (i % 4 == 3) {
          dbg("\r\n");
      }
    }
  }
}

// MIFARE Ultralight に記録された NDEF メッセージを表示
bool showMifareULNdefMessage() {
  uint8_t buf[20];
  uint8_t count = sizeof(buf);
  uint8_t page = 0x04;
  int sts = rcs620s.readMifareUL(page, buf, &count);
  if (!sts) {
      //dbg("ntagShowNdefMessage: readPages sts=%d\r\n", sts);
      return false;
  }
  if (buf[0] != 0x03) { // NDEF Message TLV
      return false;
  }
  int msgSize = (int)buf[1]; // NDEF Message size
  if (msgSize <= 0) {
      return false;
  }
  // NDEF メッセージをすべて読み込む
  uint8_t *pNdefMsgArray = (uint8_t*)malloc(msgSize);
  if (!pNdefMsgArray) {
    return false;
  }
  memset(pNdefMsgArray, 0, msgSize);
  pNdefMsgArray[0] = buf[2];
  pNdefMsgArray[1] = buf[3];

  page = 0x05;
  for (int i = 2; i < msgSize; ) {
    count = sizeof(buf);
    sts = rcs620s.readMifareUL(page, buf, &count);
    for (int j = 0; j < count/* - 2*/; j++) {
        pNdefMsgArray[i++] = buf[j];
        if (i >= msgSize) {
            break;
        }
    }
    page += 4;
  }
  // NDEF レコードを順次表示
  char *pType = NULL;
  for (int idx = 0, rec = 0; idx < msgSize; ) {
    uint8_t rFlags = pNdefMsgArray[idx++];
    int MB, ME, CF, SR, IL, TNF;
    int typeLength, idLength =0, payloadLength = 0;
    dbg("[NDEF Record #%d]\r\n", rec++);
    // MB (Message Begin)
    dbg(" MB:%d", (MB = ((rFlags & 0x80) != 0) ? 1 : 0));
    // ME (Message End)
    dbg(" ME:%d", (ME = ((rFlags & 0x40) != 0) ? 1 : 0));
    // CF (Chunk Flag)
    dbg(" CF:%d", (CF = ((rFlags & 0x20) != 0) ? 1 : 0));
    // SR (Short Record)
    dbg(" SR:%d", (SR = ((rFlags & 0x10) != 0) ? 1 : 0));
    // IL (ID_LENGTH field is present)
    dbg(" IL:%d", (IL = ((rFlags & 0x08) != 0) ? 1 : 0));
    // TNF (Type Name Format)
    dbg(" TNF:%d", (TNF = rFlags & 0x07));
    dbg("\r\n");
    // TYPE_LENGTH
    dbg(" TypeLength:%d\r\n", (typeLength = pNdefMsgArray[idx++]));
    //  PAYLOAD_LENGTH
    if (SR == 1) {
        // if set, that the PAYLOAD_LENGTH field is a single octet.
        dbg(" PayloadLength:%d\r\n", (payloadLength = pNdefMsgArray[idx++]));
    } else {
        for (int n = 0; n < 4; n++) {
            // correct??
            payloadLength += pNdefMsgArray[idx++] << (24 - n*8);
            dbg(" PayloadLength:%d\r\n", payloadLength);
        }
    }
    // ID_LENGTH
    if (IL == 1) {
        dbg(" IdLength:%d\r\n", (idLength = pNdefMsgArray[idx++]));
    }
    // TYPE
    if (pType) {
        free(pType);
        pType = NULL;
    }
    pType = (char*)malloc(typeLength+1);
    if (!pType) {
      if (pNdefMsgArray) {
        free(pNdefMsgArray);
        return false;
      }
    }
    memset(pType, 0, typeLength+1);
    for (int n = 0; n < typeLength; n++) {
        pType[n] = pNdefMsgArray[idx++];
        //dbg("%c\r\n", pType[n]);
    }
    dbg(" Type:%s\r\n", pType);
    // ID
    if (IL == 1 && idLength > 0) {
        dbg(" Id:");
        for (int n = 0; n < idLength; n++) {
            dbg("%02X", pNdefMsgArray[idx++]);
        }
        dbg("\r\n");
    }
    // TNF == 0x01 : "NFC Forum well-known type" 以外はスキップ
    if (TNF != 0x01) {
        idx += payloadLength;
        dbg(" (skipping non NFC Forum well-known type..)\r\n");
        continue;
    }
    uint8_t byteData = pNdefMsgArray[idx++];
    // Type = 'U' (URI)
    if (typeLength == 1 && pType[0] == 0x55) {
        uint8_t idCode = byteData;
        dbg("  Identifier code:0x%02X\r\n", idCode);
        dbg("  Data:[");
        for (int c = 0; c < payloadLength - 1; c++) {
            dbg("%c", pNdefMsgArray[idx++]);
        }
        dbg("]\r\n");
    }
    // Type = 'T' (Text)
    else if (typeLength == 1 && pType[0] == 0x54) {
        uint8_t encode = (uint8_t)(byteData & 0x80);
        uint8_t langCodeLen = (uint8_t)(byteData & 0x3F);
        dbg("  Encode:%s\r\n", ((encode == 0) ? "UTF-8" : "UTF-16"));
        dbg("  LangCodeLength:%d\r\n", langCodeLen);
        dbg("  LangCode:");
        for (int n = 0; n < langCodeLen; n++) {
            dbg("%c", pNdefMsgArray[idx++]);
        }
        dbg("\r\n");
        dbg("  Data:[");
        for (int c = 0; c < payloadLength - (langCodeLen + 1); c++) {
            dbg("%c", pNdefMsgArray[idx++]);
        }
        dbg("]\r\n");
    } else {
        dbg(" (require NFC Forum well-known type 'T' or 'U'..)\r\n");
        idx += payloadLength;
    }
  }
  if (pType) {
      free(pType);
  }
  if (pNdefMsgArray) {
      free(pNdefMsgArray);
  }
  return true;
}

