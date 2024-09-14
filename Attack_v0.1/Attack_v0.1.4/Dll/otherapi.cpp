#include "ntapi.hpp"
#include "otherapi.hpp"

void Fastmemcpy(void* dest, void* src, int size)
{
	uint8_t* pdest = (uint8_t*)dest;
	uint8_t* psrc = (uint8_t*)src;
	//Fast 4 bytes->1 byte 
	int loops = (size / sizeof(uint32_t));
	for (int index = 0; index < loops; ++index)
	{
		*((uint32_t*)pdest) = *((uint32_t*)psrc);
		pdest += sizeof(uint32_t);
		psrc += sizeof(uint32_t);
	}

	loops = (size % sizeof(uint32_t));
	for (int index = 0; index < loops; ++index)
	{
		*pdest = *psrc;
		++pdest;
		++psrc;
	}
}
