# SPDX-FileCopyrightText: 2021 Andrius Štikonas <andrius@stikonas.eu>
#
# SPDX-License-Identifier: GPL-3.0-or-later

src_prepare() {
    default

    # Regenerate bison files
    rm -f perly.c perly.h
    bison -d perly.y
    mv perly.tab.c perly.c
    mv perly.tab.h perly.h

    # Regenerate other prebuilt header files
    for file in embed keywords opcode; do
        rm -f ${file}.h
        perl ${file}.pl
    done
}

src_install() {
    # Remove old perl
    rm -rf "${PREFIX}"/lib/perl5/

    default
}
