/*
 * ColdFire UART emulation.
 *
 * Copyright (c) 2007 CodeSourcery.
 *
 * This code is licenced under the GPL
 */
#include "hw.h"
#include "mcf.h"
#include "qemu-char.h"

typedef struct {
    uint8_t mr[2];
    uint8_t sr;
    uint8_t isr;
    uint8_t imr;
    uint8_t bg1;
    uint8_t bg2;
    uint8_t fifo[4];
    uint8_t tb;
    int current_mr;
    int fifo_len;
    int tx_enabled;
    int rx_enabled;
    qemu_irq irq;
    CharDriverState *chr;
} mcf_uart_state;

/* UART Status Register bits.  */
#define MCF_UART_RxRDY  0x01
#define MCF_UART_FFULL  0x02
#define MCF_UART_TxRDY  0x04
#define MCF_UART_TxEMP  0x08
#define MCF_UART_OE     0x10
#define MCF_UART_PE     0x20
#define MCF_UART_FE     0x40
#define MCF_UART_RB     0x80

/* Interrupt flags.  */
#define MCF_UART_TxINT  0x01
#define MCF_UART_RxINT  0x02
#define MCF_UART_DBINT  0x04
#define MCF_UART_COSINT 0x80

/* UMR1 flags.  */
#define MCF_UART_BC0    0x01
#define MCF_UART_BC1    0x02
#define MCF_UART_PT     0x04
#define MCF_UART_PM0    0x08
#define MCF_UART_PM1    0x10
#define MCF_UART_ERR    0x20
#define MCF_UART_RxIRQ  0x40
#define MCF_UART_RxRTS  0x80

static void mcf_uart_update(mcf_uart_state *s)
{
    s->isr &= ~(MCF_UART_TxINT | MCF_UART_RxINT);
    if (s->sr & MCF_UART_TxRDY)
        s->isr |= MCF_UART_TxINT;
    if ((s->sr & ((s->mr[0] & MCF_UART_RxIRQ)
                  ? MCF_UART_FFULL : MCF_UART_RxRDY)) != 0)
        s->isr |= MCF_UART_RxINT;

    qemu_set_irq(s->irq, (s->isr & s->imr) != 0);
}

uint32_t mcf_uart_read(void *opaque, target_phys_addr_t addr)
{
    mcf_uart_state *s = (mcf_uart_state *)opaque;
    switch (addr & 0x3f) {
    case 0x00:
        return s->mr[s->current_mr];
    case 0x04:
        return s->sr;
    case 0x0c:
        {
            uint8_t val;
            int i;

            if (s->fifo_len == 0)
                return 0;

            val = s->fifo[0];
            s->fifo_len--;
            for (i = 0; i < s->fifo_len; i++)
                s->fifo[i] = s->fifo[i + 1];
            s->sr &= ~MCF_UART_FFULL;
            if (s->fifo_len == 0)
                s->sr &= ~MCF_UART_RxRDY;
            mcf_uart_update(s);
            qemu_chr_accept_input(s->chr);
            return val;
        }
    case 0x10:
        /* TODO: Implement IPCR.  */
        return 0;
    case 0x14:
        return s->isr;
    case 0x18:
        return s->bg1;
    case 0x1c:
        return s->bg2;
    default:
        return 0;
    }
}

/* Update TxRDY flag and set data if present and enabled.  */
static void mcf_uart_do_tx(mcf_uart_state *s)
{
    if (s->tx_enabled && (s->sr & MCF_UART_TxEMP) == 0) {
        if (s->chr)
            qemu_chr_write(s->chr, (unsigned char *)&s->tb, 1);
        s->sr |= MCF_UART_TxEMP;
    }
    if (s->tx_enabled) {
        s->sr |= MCF_UART_TxRDY;
    } else {
        s->sr &= ~MCF_UART_TxRDY;
    }
}

static void mcf_do_command(mcf_uart_state *s, uint8_t cmd)
{
    /* Misc command.  */
    switch ((cmd >> 4) & 3) {
    case 0: /* No-op.  */
        break;
    case 1: /* Reset mode register pointer.  */
        s->current_mr = 0;
        break;
    case 2: /* Reset receiver.  */
        s->rx_enabled = 0;
        s->fifo_len = 0;
        s->sr &= ~(MCF_UART_RxRDY | MCF_UART_FFULL);
        break;
    case 3: /* Reset transmitter.  */
        s->tx_enabled = 0;
        s->sr |= MCF_UART_TxEMP;
        s->sr &= ~MCF_UART_TxRDY;
        break;
    case 4: /* Reset error status.  */
        break;
    case 5: /* Reset break-change interrupt.  */
        s->isr &= ~MCF_UART_DBINT;
        break;
    case 6: /* Start break.  */
    case 7: /* Stop break.  */
        break;
    }

    /* Transmitter command.  */
    switch ((cmd >> 2) & 3) {
    case 0: /* No-op.  */
        break;
    case 1: /* Enable.  */
        s->tx_enabled = 1;
        mcf_uart_do_tx(s);
        break;
    case 2: /* Disable.  */
        s->tx_enabled = 0;
        mcf_uart_do_tx(s);
        break;
    case 3: /* Reserved.  */
        fprintf(stderr, "mcf_uart: Bad TX command\n");
        break;
    }

    /* Receiver command.  */
    switch (cmd & 3) {
    case 0: /* No-op.  */
        break;
    case 1: /* Enable.  */
        s->rx_enabled = 1;
        break;
    case 2:
        s->rx_enabled = 0;
        break;
    case 3: /* Reserved.  */
        fprintf(stderr, "mcf_uart: Bad RX command\n");
        break;
    }
}

void mcf_uart_write(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    mcf_uart_state *s = (mcf_uart_state *)opaque;
    switch (addr & 0x3f) {
    case 0x00:
        s->mr[s->current_mr] = val;
        s->current_mr = 1;
        break;
    case 0x04:
        /* CSR is ignored.  */
        break;
    case 0x08: /* Command Register.  */
        mcf_do_command(s, val);
        break;
    case 0x0c: /* Transmit Buffer.  */
        s->sr &= ~MCF_UART_TxEMP;
        s->tb = val;
        mcf_uart_do_tx(s);
        break;
    case 0x10:
        /* ACR is ignored.  */
        break;
    case 0x14:
        s->imr = val;
        break;
    default:
        break;
    }
    mcf_uart_update(s);
}

static void mcf_uart_reset(mcf_uart_state *s)
{
    s->fifo_len = 0;
    s->mr[0] = 0;
    s->mr[1] = 0;
    s->sr = MCF_UART_TxEMP;
    s->tx_enabled = 0;
    s->rx_enabled = 0;
    s->isr = 0;
    s->imr = 0;
}

static void mcf_uart_push_byte(mcf_uart_state *s, uint8_t data)
{
    /* Break events overwrite the last byte if the fifo is full.  */
    if (s->fifo_len == 4)
        s->fifo_len--;

    s->fifo[s->fifo_len] = data;
    s->fifo_len++;
    s->sr |= MCF_UART_RxRDY;
    if (s->fifo_len == 4)
        s->sr |= MCF_UART_FFULL;

    mcf_uart_update(s);
}

static void mcf_uart_event(void *opaque, int event)
{
    mcf_uart_state *s = (mcf_uart_state *)opaque;

    switch (event) {
    case CHR_EVENT_BREAK:
        s->isr |= MCF_UART_DBINT;
        mcf_uart_push_byte(s, 0);
        break;
    default:
        break;
    }
}

static int mcf_uart_can_receive(void *opaque)
{
    mcf_uart_state *s = (mcf_uart_state *)opaque;

    return s->rx_enabled && (s->sr & MCF_UART_FFULL) == 0;
}

static void mcf_uart_receive(void *opaque, const uint8_t *buf, int size)
{
    mcf_uart_state *s = (mcf_uart_state *)opaque;

    mcf_uart_push_byte(s, buf[0]);
}

static const QemuChrHandlers mcf_uart_handlers = {
    .fd_can_read = mcf_uart_can_receive,
    .fd_read = mcf_uart_receive,
    .fd_event = mcf_uart_event,
};

void *mcf_uart_init(qemu_irq irq, CharDriverState *chr)
{
    mcf_uart_state *s;

    s = qemu_mallocz(sizeof(mcf_uart_state));
    s->chr = chr;
    s->irq = irq;
    if (chr) {
        qemu_chr_add_handlers(chr, &mcf_uart_handlers, s);
    }
    mcf_uart_reset(s);
    return s;
}


static CPUReadMemoryFunc * const mcf_uart_readfn[] = {
   mcf_uart_read,
   mcf_uart_read,
   mcf_uart_read
};

static CPUWriteMemoryFunc * const mcf_uart_writefn[] = {
   mcf_uart_write,
   mcf_uart_write,
   mcf_uart_write
};

void mcf_uart_mm_init(target_phys_addr_t base, qemu_irq irq,
                      CharDriverState *chr)
{
    mcf_uart_state *s;
    int iomemtype;

    s = mcf_uart_init(irq, chr);
    iomemtype = cpu_register_io_memory(mcf_uart_readfn,
                                       mcf_uart_writefn, s,
                                       DEVICE_NATIVE_ENDIAN);
    cpu_register_physical_memory(base, 0x40, iomemtype);
}
