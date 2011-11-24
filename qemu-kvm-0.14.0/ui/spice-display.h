/*
 * Copyright (C) 2010 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 or
 * (at your option) version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <spice/ipc_ring.h>
#include <spice/enums.h>
#include <spice/qxl_dev.h>

#include "pflib.h"

#define NUM_MEMSLOTS 8
#define MEMSLOT_GENERATION_BITS 8
#define MEMSLOT_SLOT_BITS 8

#define MEMSLOT_GROUP_HOST  0
#define MEMSLOT_GROUP_GUEST 1
#define NUM_MEMSLOTS_GROUPS 2

#define NUM_SURFACES 1024

/*
 * Commands/requests from server thread to iothread.
 * Note that CREATE_UPDATE is used both with qxl and without it (spice-display)
 * the others are only used with the qxl device.
 *
 * SET_IRQ - just the request is sent (1 byte)
 * CREATE_UPDATE - jus the request is sent (1 byte)
 * CURSOR_SET - send QXLServerRequestCursorSet
 * CURSOR_MOVE - send QXLServerRequestCursorMove
 */
#define QXL_EMPTY_UPDATE ((void *)-1)
enum {
    QXL_SERVER_SET_IRQ = 1,
    QXL_SERVER_CREATE_UPDATE,
    QXL_SERVER_CURSOR_SET,
    QXL_SERVER_CURSOR_MOVE
};

struct SimpleSpiceUpdate;

typedef struct SimpleSpiceDisplay {
    DisplayState *ds;
    void *buf;
    int bufsize;
    QXLWorker *worker;
    QXLInstance qxl;
    uint32_t unique;
    QemuPfConv *conv;

    QXLRect dirty;
    int notify;
    int running;

    /* thread signaling - used both in qxl (in vga mode
     * and in native mode) and without qxl */
    pthread_t          main;
    int                pipe[2];     /* to iothread */

    /* ssd updates (one request/command at a time) */
    struct SimpleSpiceUpdate *update;
    int waiting_for_update;
} SimpleSpiceDisplay;

typedef struct SimpleSpiceUpdate {
    QXLDrawable drawable;
    QXLImage image;
    QXLCommandExt ext;
    uint8_t *bitmap;
} SimpleSpiceUpdate;

int qemu_spice_rect_is_empty(const QXLRect* r);
void qemu_spice_rect_union(QXLRect *dest, const QXLRect *r);

SimpleSpiceUpdate *qemu_spice_create_update(SimpleSpiceDisplay *sdpy);
void qemu_spice_destroy_update(SimpleSpiceDisplay *sdpy, SimpleSpiceUpdate *update);
void qemu_spice_create_host_memslot(SimpleSpiceDisplay *ssd);
void qemu_spice_create_host_primary(SimpleSpiceDisplay *ssd);
void qemu_spice_destroy_host_primary(SimpleSpiceDisplay *ssd);
void qemu_spice_vm_change_state_handler(void *opaque, int running, int reason);

void qemu_spice_display_update(SimpleSpiceDisplay *ssd,
                               int x, int y, int w, int h);
void qemu_spice_display_resize(SimpleSpiceDisplay *ssd);
void qemu_spice_display_refresh(SimpleSpiceDisplay *ssd);
/* shared with qxl.c in vga mode and ui/spice-display (no qxl mode) */
int qxl_vga_mode_get_command(
    SimpleSpiceDisplay *ssd, struct QXLCommandExt *ext);
/* used by both qxl and spice-display */
void qxl_create_server_to_iothread_pipe(SimpleSpiceDisplay *ssd,
    IOHandler *pipe_read);
