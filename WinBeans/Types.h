#pragma once

// Don't judge, please
#undef VOID
typedef void VOID;

typedef struct
Heading {
	LPWSTR	headerName;
	int32_t		indentLvl{};
	HTREEITEM	childHeader;
} Heading;

typedef struct
HEADER_STRINGS {
	LPWSTR	name = NULL;
	LPWSTR	member = NULL;
	LPWSTR	value = NULL;
	LPWSTR	description = NULL;
} HEADER_STRINGS;

enum   selectedHdr { BASENAME = 0, DOSHDR, NTHDR, NTSIG, FILEHDR, OPTHDR, SECHDR };
enum   columns	   { NAME = 0, MEMBER, VALUE, DESCRIPTION};