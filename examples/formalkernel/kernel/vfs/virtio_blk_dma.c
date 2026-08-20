/* M56 kernel-side DMA mapping witness. Device behavior remains unverified. */
void map_virtio_blk_request(void *buffer) {
    dma_map(blk_dev, buffer, 512);
}
