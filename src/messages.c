/**
 * \file messages.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - NETCONF messages functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libyang/libyang.h>

#include "config.h"
#include "messages.h"
#include "messages_p.h"

API void
nc_notif_free(struct nc_notif *notif)
{
    if (!notif) {
        return;
    }

    lydict_remove(notif->tree->schema->module->ctx, notif->datetime);
    lyd_free(notif->tree);
    free(notif);
}
