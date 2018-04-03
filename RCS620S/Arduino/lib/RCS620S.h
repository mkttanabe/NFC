/*
 * RC-S620/S sample library for Arduino
 *
 * Copyright 2010 Sony Corporation
 *
 * Last Modified Date: 2018-03-16
 * Last Modified By: KLab Inc.
 *
 */

#include <inttypes.h>

#ifndef RCS620S_H_
#define RCS620S_H_

#define KLAB

#ifdef KLAB
enum PICC_TYPE {
    PICC_UNKNOWN = 0,
    PICC_FELICA,
    PICC_ISO_IEC14443_TypeA_MIFARE,
    PICC_ISO_IEC14443_TypeA_MIFAREUL,
    PICC_ISO_IEC14443_TypeB
};
#define TOTALPAGES_NTAG213   45 // 0x2D
#define TOTALPAGES_NTAG215  135 // 0x87
#define TOTALPAGES_NTAG216  231 // 0xE7
#endif // KLAB

/* --------------------------------
 * Constant
 * -------------------------------- */

#define RCS620S_MAX_CARD_RESPONSE_LEN    254
#define RCS620S_MAX_RW_RESPONSE_LEN      265

/* --------------------------------
 * Class Declaration
 * -------------------------------- */

class RCS620S
{
public:
    RCS620S();

    int initDevice(void);
    int polling(uint16_t systemCode = 0xffff);
#ifdef KLAB
    int polling_felica(uint16_t systemCode = 0xffff);
    int polling_typeA();
    int polling_typeB();
    uint8_t getTotalPagesMifareUL(void);
    int readMifareUL(uint8_t startPage, uint8_t *buf, uint8_t *size);
#endif // KLAB
    int cardCommand(
        const uint8_t* command,
        uint8_t commandLen,
        uint8_t response[RCS620S_MAX_CARD_RESPONSE_LEN],
        uint8_t* responseLen);
    int rfOff(void);

    int push(
        const uint8_t* data,
        uint8_t dataLen);

private:
    int rwCommand(
        const uint8_t* command,
        uint16_t commandLen,
        uint8_t response[RCS620S_MAX_RW_RESPONSE_LEN],
        uint16_t* responseLen);
    void cancel(void);
    uint8_t calcDCS(
        const uint8_t* data,
        uint16_t len);

    void writeSerial(
        const uint8_t* data,
        uint16_t len);
    int readSerial(
        uint8_t* data,
        uint16_t len);
    void flushSerial(void);

    int checkTimeout(unsigned long t0);

public:
    unsigned long timeout;
    uint8_t idm[8];
    uint8_t pmm[8];
#ifdef KLAB
	uint8_t idLength;
	uint8_t piccType;
#endif // KLAB
};

#endif /* !RCS620S_H_ */
