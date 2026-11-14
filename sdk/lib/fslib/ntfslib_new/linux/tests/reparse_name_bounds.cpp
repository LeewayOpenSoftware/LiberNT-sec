/*
 * Junction and symbolic-link reparse data must keep both names inside the
 * data: the I/O manager follows the name offsets when it reparses an open.
 * Setting such a buffer is rejected before the record is touched, and the
 * name parser used at open time agrees.
 */

#include <cstdio>
#include <cstring>

#include <ntfslib_new.h>
#include <ntfslib_new_internal.h>

static int Failures;

static void
Check(bool Condition, const char* Message)
{
    if (!Condition)
    {
        std::fprintf(stderr, "reparse_name_bounds: %s\n", Message);
        Failures++;
    }
}

static void
Put16(UCHAR* Buffer, ULONG Offset, USHORT Value)
{
    std::memcpy(Buffer + Offset, &Value, sizeof(Value));
}

static void
Put32(UCHAR* Buffer, ULONG Offset, ULONG Value)
{
    std::memcpy(Buffer + Offset, &Value, sizeof(Value));
}

/* Build a mount-point (Symlink = false) or symbolic-link buffer holding the
 * substitute name then the print name, with the four name fields given. */
static ULONG
Build(UCHAR* Buffer,
      bool Symlink,
      USHORT SubstituteOffset,
      USHORT SubstituteLength,
      USHORT PrintOffset,
      USHORT PrintLength)
{
    static const WCHAR Names[] = L"\\??\\C:\\t\\C:\\t\\";
    const ULONG NameHeader = Symlink ? 12 : 8;
    const ULONG PathBytes = sizeof(Names) - sizeof(WCHAR);
    const ULONG DataLength = NameHeader + PathBytes;

    std::memset(Buffer, 0, 64 + PathBytes);
    Put32(Buffer, 0, Symlink ? NTFS_IO_REPARSE_TAG_SYMLINK : NTFS_IO_REPARSE_TAG_MOUNT_POINT);
    Put16(Buffer, 4, (USHORT)DataLength);
    Put16(Buffer, 8, SubstituteOffset);
    Put16(Buffer, 10, SubstituteLength);
    Put16(Buffer, 12, PrintOffset);
    Put16(Buffer, 14, PrintLength);
    if (Symlink)
        Put32(Buffer, 16, 0);
    std::memcpy(Buffer + 8 + NameHeader, Names, PathBytes);
    return 8 + DataLength;
}

static NTSTATUS
TrySet(const UCHAR* Buffer, ULONG Length)
{
    /* No volume: a rejected buffer must return before the record is used. */
    FileRecord Record(nullptr, 1024);

    return Record.SetReparsePoint(Buffer, Length);
}

static bool
Parses(const UCHAR* Buffer, ULONG Length)
{
    NtfsReparseNameView View;

    return NT_SUCCESS(NtfsParseNameSurrogateReparsePoint(Buffer, Length, &View));
}

int
main()
{
    UCHAR Buffer[256];
    ULONG Length;

    /* The 28-byte path buffer holds "\??\C:\t\" (18 bytes) then "C:\t\" (10). */
    for (int Symlink = 0; Symlink < 2; Symlink++)
    {
        const char* Kind = Symlink ? "symlink" : "mount point";

        Length = Build(Buffer, Symlink, 0, 18, 18, 10);
        Check(Parses(Buffer, Length), Kind);

        struct
        {
            USHORT SubstituteOffset, SubstituteLength, PrintOffset, PrintLength;
            const char* What;
        } Bad[] = {
            { 0x3000, 18, 18, 10, "substitute offset beyond the data" },
            { 20, 18, 0, 0, "substitute range past the end" },
            { 0xFFFE, 4, 0, 0, "substitute offset + length wraps a USHORT" },
            { 1, 18, 18, 10, "odd substitute offset" },
            { 0, 17, 18, 10, "odd substitute length" },
            { 0, 0, 18, 10, "empty substitute name" },
            { 0, 18, 0x2000, 10, "print offset beyond the data" },
            { 0, 18, 24, 10, "print range past the end" },
        };

        for (const auto& Case : Bad)
        {
            char Message[160];

            Length = Build(Buffer, Symlink, Case.SubstituteOffset, Case.SubstituteLength,
                           Case.PrintOffset, Case.PrintLength);
            std::snprintf(Message, sizeof(Message), "%s: %s accepted by the parser", Kind, Case.What);
            Check(!Parses(Buffer, Length), Message);
            std::snprintf(Message, sizeof(Message), "%s: %s accepted by SetReparsePoint", Kind, Case.What);
            Check(TrySet(Buffer, Length) == STATUS_IO_REPARSE_DATA_INVALID, Message);
        }

        /* Truncated buffers: the declared data no longer matches the length. */
        Length = Build(Buffer, Symlink, 0, 18, 18, 10);
        Check(TrySet(Buffer, Length - 2) == STATUS_IO_REPARSE_DATA_INVALID, "truncated buffer accepted");
        Check(TrySet(Buffer, 8 + 4) == STATUS_IO_REPARSE_DATA_INVALID, "header-only buffer accepted");
    }

    /* An embedded NUL in a name is rejected too. */
    Length = Build(Buffer, false, 0, 18, 18, 10);
    Put16(Buffer, 16 + 4, 0);
    Check(TrySet(Buffer, Length) == STATUS_IO_REPARSE_DATA_INVALID, "NUL inside the substitute name accepted");

    if (Failures)
        return 1;
    std::printf("reparse_name_bounds: passed\n");
    return 0;
}
