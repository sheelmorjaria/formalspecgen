/* FormalKernel DMA source — the netif driver seam lwIP leaves to the
 * port (src/netif/ethernetif.c shape): the NIC's descriptors are
 * mapped through the platform DMA API before the RX ring sees them.
 * The device and mapping size must live inside the DmaContract
 * declared in the profile — the M39/M45 gates judge this call site.
 */
void *nic_setup(void) {
    return dma_map(nic_dev, 0x100);
}
