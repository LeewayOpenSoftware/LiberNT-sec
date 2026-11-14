/*
 * PROJECT:     LiberNT host-native tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Debug print macros for the host build of oplock.c. Arguments are not
 *              evaluated, as in a free kernel build (oplock.c has a DPRINT naming an
 *              identifier that does not exist, which only compiles because of that).
 * COPYRIGHT:   Copyright 2026 Leeway Open Software
 */
#ifndef FSRTL_HOST_DEBUG_H
#define FSRTL_HOST_DEBUG_H

#define DPRINT(...) do { } while (0)
#define DPRINT1(...) do { } while (0)

#endif /* FSRTL_HOST_DEBUG_H */
