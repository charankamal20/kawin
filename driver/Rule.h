#pragma once
#include <fltKernel.h>
#include <ntstrsafe.h>

#define RULE_ENTRY_TAG 'rulE'
#define RULE_PATH_TAG 'rulP'

#define NUM_BUCKETS 61  // prime no.

enum class RuleAction : short {
    Audit,
    Block,
    Allow
};

typedef struct _RULE_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Path;
    RuleAction Action;
} RULE_ENTRY, * PRULE_ENTRY;

PRULE_ENTRY AllocateRuleEntry(_In_ PUNICODE_STRING Path, _In_ RuleAction Action);
VOID FreeRuleEntry(_In_ PRULE_ENTRY Entry);

ULONG HashPath(_In_ PUNICODE_STRING Path);
BOOLEAN MatchPath(_In_ PRULE_ENTRY Entry, _In_ PUNICODE_STRING Path);

