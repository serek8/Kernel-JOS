#include <error.h>
#include <stdio.h>
#include <ahci.h>
#include <ata.h>
#include <pci.h>

#include <kernel/dev/disk.h>
#include <kernel/dev/pci.h>
#include <kernel/mem.h>

#define HBA_PORT_IPM_ACTIVE 1
#define HBA_PORT_DET_PRESENT 3
 
static struct pci_device_id compat[] = {
	PCI_MATCH_CLASS(1, 6),
	{},
};

void start_cmd(volatile struct hba_port *port)
{
	/* Wait until CR is clear. */
	while (port->cmd & HBA_PxCMD_CR);

	/* Set FRE and ST. */
	port->cmd |= HBA_PxCMD_FRE | HBA_PxCMD_ST;
}

void stop_cmd(volatile struct hba_port *port)
{
	/* Clear ST. */
	port->cmd &= ~HBA_PxCMD_ST;

	/* Wait until FR and CR are cleared. */
	while (port->cmd & (HBA_PxCMD_FR | HBA_PxCMD_CR));

	/* Clear FR. */
	port->cmd &= ~HBA_PxCMD_FRE;
}

void port_rebase(volatile struct hba_port *port, int port_no)
{
	port->int_stat = 0;
}

int find_cmdslot(volatile struct hba_port *port)
{
	size_t i;
	uint32_t slots = (port->sata_act | port->cmd_issue);

	for (i = 0; i < 32; ++i) {
		if (!(slots & 1)) {
			return i;
		}

		slots >>= 1;
	}

	return -1;
}

enum ahci_state {
	AHCI_IDLE,
	AHCI_READ,
	AHCI_WRITE,
};

struct ahci_disk {
	struct disk disk;
	volatile struct hba_port *port;
	enum ahci_state state;
	size_t sect_size;
	int slot;
};

int ahci_poll(struct disk *disk)
{
	struct ahci_disk *ahci_disk = container_of(disk, struct ahci_disk,
		disk);
	volatile struct hba_port *port = ahci_disk->port;

	return !(port->cmd_issue & (1 << ahci_disk->slot)) ||
		(port->int_stat & HBA_PxIS_TFES);
}

int64_t ahci_read(struct disk *disk, void *buf, size_t count, uint64_t addr)
{
	struct fis_reg_h2d *cmd_fis;
	struct hba_cmd_hdr *hdr;
	struct hba_cmd_tbl *tbl;
	struct hba_prdt *prdt;
	struct ahci_disk *ahci_disk = container_of(disk, struct ahci_disk,
		disk);
	volatile struct hba_port *port = ahci_disk->port;
	uint32_t *data = buf;
	size_t i;

	/* Ensure that the buffer is 1024 kiB aligned. */
	assert(!((uintptr_t)buf & (1024 - 1)));

	if (ahci_disk->state == AHCI_IDLE) {
		/* The disk is currently idle. Find an available command slot
		 * to use to issue a read request.
		 */
		ahci_disk->slot = find_cmdslot(port);

		if (ahci_disk->slot < 0) {
			return -ENOMEM;
		}

		if (!count) {
			return 0;
		}

		/* Set up the command header. */
		hdr = (struct hba_cmd_hdr *)KADDR(port->cmd_base);
		hdr += ahci_disk->slot;
		hdr->cmd_fis_len = sizeof *cmd_fis / sizeof(uint32_t);
		hdr->write = 0;
		hdr->prefetchable = 1;
		hdr->clear_busy = 1;
		hdr->prdt_len = ((count - 1) / 16) + 1;

		/* Reset the table. */
		tbl = (struct hba_cmd_tbl *)KADDR(hdr->cmd_base);
		memset(tbl, 0, sizeof *tbl);
		prdt = tbl->prdts;

		/* Set up 8 kiB reads (16 sectors) per PRDT. */
		for (i = 0; i < hdr->prdt_len - 1; ++i, ++prdt) {
			prdt->data_base = PADDR(data);
			prdt->size = 8 * 1024 - 1;
			prdt->i = 0;
			data += 2 * 1024;
			count -= 16;
		}

		/* Set up the final entry. */
		prdt->data_base = PADDR(data);
		prdt->size = (count / ahci_disk->sect_size) - 1;
		prdt->i = 0;

		/* Set up the command. */
		cmd_fis = (struct fis_reg_h2d *)&tbl->cmd_fis;

		cmd_fis->fis_type = FIS_TYPE_REG_H2D;
		cmd_fis->c = 1;
		cmd_fis->cmd = ATA_CMD_READ_DMA_EX;

		cmd_fis->lba0 = addr & 0xff;
		cmd_fis->lba1 = (addr >> 8) & 0xff;
		cmd_fis->lba2 = (addr >> 16) & 0xff;
		cmd_fis->dev = 1 << 6;

		cmd_fis->lba3 = (addr >> 24) & 0xff;
		cmd_fis->lba4 = (addr >> 32) & 0xff;
		cmd_fis->lba5 = (addr >> 40) & 0xff;

		cmd_fis->count = count;

		/* Wait before issuing the new command. */
		while (port->task_file_data & (ATA_STAT_BUSY | ATA_STAT_DRQ));

		/* Issue the command. */
		port->cmd_issue = 1 << ahci_disk->slot;

		ahci_disk->state = AHCI_READ;

		return -EAGAIN;
	}

	if (ahci_disk->state != AHCI_READ) {
		/* The disk is currently not available. */
		return -EAGAIN;
	}

	if (!ahci_poll(disk)) {
		/* The disk is not ready yet. */
		return -EAGAIN;
	}

	ahci_disk->state = AHCI_IDLE;

	if (port->int_stat& HBA_PxIS_TFES) {
		return 0;
	}

	return count * ahci_disk->sect_size;
}

int64_t ahci_write(struct disk *disk, const void *buf, size_t count, uint64_t addr)
{
	struct fis_reg_h2d *cmd_fis;
	struct hba_cmd_hdr *hdr;
	struct hba_cmd_tbl *tbl;
	struct hba_prdt *prdt;
	struct ahci_disk *ahci_disk = container_of(disk, struct ahci_disk,
		disk);
	volatile struct hba_port *port = ahci_disk->port;
	uint32_t *data = (uint32_t *)buf;
	size_t i;

	/* Ensure that the buffer is 1024 kiB aligned. */
	assert(!((uintptr_t)buf & (1024 - 1)));

	if (ahci_disk->state == AHCI_IDLE) {
		/* The disk is currently idle. Find an available command slot
		 * to use to issue a read request.
		 */
		ahci_disk->slot = find_cmdslot(port);

		if (ahci_disk->slot < 0) {
			return -ENOMEM;
		}

		if (!count) {
			return 0;
		}

		/* Set up the command header. */
		hdr = (struct hba_cmd_hdr *)KADDR(port->cmd_base);
		hdr += ahci_disk->slot;
		hdr->cmd_fis_len = sizeof *cmd_fis / sizeof(uint32_t);
		hdr->write = 1;
		hdr->prefetchable = 1;
		hdr->clear_busy = 1;
		hdr->prdt_len = ((count - 1) / 16) + 1;

		/* Reset the table. */
		tbl = (struct hba_cmd_tbl *)KADDR(hdr->cmd_base);
		memset(tbl, 0, sizeof *tbl);
		prdt = tbl->prdts;

		/* Set up 8 kiB reads (16 sectors) per PRDT. */
		for (i = 0; i < hdr->prdt_len - 1; ++i, ++prdt) {
			prdt->data_base = PADDR(data);
			prdt->size = 8 * 1024 - 1;
			prdt->i = 0;
			data += 2 * 1024;
			count -= 16;
		}

		/* Set up the final entry. */
		prdt->data_base = PADDR(data);
		prdt->size = (count / ahci_disk->sect_size) - 1;
		prdt->i = 0;

		/* Set up the command. */
		cmd_fis = (struct fis_reg_h2d *)&tbl->cmd_fis;

		cmd_fis->fis_type = FIS_TYPE_REG_H2D;
		cmd_fis->c = 1;
		cmd_fis->cmd = ATA_CMD_WRITE_DMA_EX;

		cmd_fis->lba0 = addr & 0xff;
		cmd_fis->lba1 = (addr >> 8) & 0xff;
		cmd_fis->lba2 = (addr >> 16) & 0xff;
		cmd_fis->dev = 1 << 6;

		cmd_fis->lba3 = (addr >> 24) & 0xff;
		cmd_fis->lba4 = (addr >> 32) & 0xff;
		cmd_fis->lba5 = (addr >> 40) & 0xff;

		cmd_fis->count = count;

		/* Wait before issuing the new command. */
		while (port->task_file_data & (ATA_STAT_BUSY | ATA_STAT_DRQ));

		/* Issue the command. */
		port->cmd_issue = 1 << ahci_disk->slot;

		ahci_disk->state = AHCI_WRITE;

		return -EAGAIN;
	}

	if (ahci_disk->state != AHCI_WRITE) {
		/* The disk is currently not available. */
		return -EAGAIN;
	}

	if (!ahci_poll(disk)) {
		/* The disk is not ready yet. */
		return -EAGAIN;
	}

	ahci_disk->state = AHCI_IDLE;

	if (port->int_stat& HBA_PxIS_TFES) {
		return 0;
	}

	return count * ahci_disk->sect_size;
}

struct disk_ops ahci_ops = {
	.poll = ahci_poll,
	.read = ahci_read,
	.write = ahci_write,
};

static int check_type(volatile struct hba_port *port)
{
	uint32_t ssts = port->sata_stat;
 
	uint8_t ipm = (ssts >> 8) & 0x0F;
	uint8_t det = ssts & 0x0F;
 
	if (det != HBA_PORT_DET_PRESENT)	// Check drive status
		return AHCI_DEV_NULL;
	if (ipm != HBA_PORT_IPM_ACTIVE)
		return AHCI_DEV_NULL;
 
	switch (port->sig)
	{
	case SATA_SIG_ATAPI:
		return AHCI_DEV_SATAPI;
	case SATA_SIG_SEMB:
		return AHCI_DEV_SEMB;
	case SATA_SIG_PM:
		return AHCI_DEV_PM;
	default:
		return AHCI_DEV_SATA;
	}
}

const char *ahci_types[] = {
	"none", "SATA", "SEMB", "PM", "SATAPI",
};

int ahci_probe(struct pci_dev *dev)
{
	struct ahci_disk *ahci_disk;
	uint32_t base, size;
	volatile struct hba_mem *abar;
	volatile struct hba_port *port;
	int dev_type;

	pci_read_bar(&base, &size, dev, 5);

	abar = mmio_map_region(base, size);

	if (!abar) {
		return -1;
	}

	size_t i;

	for (i = 0; i < 32; ++i) {
		/* Check if the port is implemented. */
		if (!(abar->pts_impl & (1 << i))) {
			continue;
		}
	
		/* Get the device type. */
		dev_type = check_type(abar->ports + i);

		if (dev_type == AHCI_DEV_NULL) {
			continue;
		}

		/* Found an actual port. */
		cprintf("AHCI: %s at port %u\n",
			ahci_types[dev_type], i);

		port = abar->ports + i;

		port_rebase(port, i);

		if (ndisks >= MAX_DISKS) {
			continue;
		}

		/* Try to allocate a new disk. */
		ahci_disk = kmalloc(sizeof *ahci_disk);

		if (!ahci_disk) {
			continue;
		}

		ahci_disk->port = port;
		ahci_disk->state = AHCI_IDLE;
		ahci_disk->sect_size = 512;
		ahci_disk->slot = -1;
		ahci_disk->disk.ops = &ahci_ops;

		/* Add the disk to the array. */
		disks[ndisks++] = &ahci_disk->disk;
	}

	return 0;
}

struct pci_driver ahci_driver = {
	.compat = compat,
	.probe = ahci_probe,
};

