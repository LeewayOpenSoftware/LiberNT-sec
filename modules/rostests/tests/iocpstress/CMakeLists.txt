# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 Leeway Open Software
add_executable(iocpstress iocpstress.c)
set_module_type(iocpstress win32cui ENTRYPOINT mainCRTStartup)
add_importlibs(iocpstress msvcrt kernel32)
add_rostests_file(TARGET iocpstress)
