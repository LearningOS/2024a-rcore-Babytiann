use super::{
    block_cache_sync_all, get_block_cache, Bitmap, BlockDevice, DiskInode, DiskInodeType, Inode,
    SuperBlock,
};
use crate::BLOCK_SZ;
use alloc::sync::Arc;
use spin::Mutex;
///An easy file system on block
pub struct EasyFileSystem {
    ///Real device
    pub block_device: Arc<dyn BlockDevice>,
    ///Inode bitmap
    pub inode_bitmap: Bitmap,
    ///Data bitmap
    pub data_bitmap: Bitmap,
    inode_area_start_block: u32,
    data_area_start_block: u32,
}

type DataBlock = [u8; BLOCK_SZ];
/// An easy fs over a block device
impl EasyFileSystem {
    /// A data block of block size
    pub fn create(
        block_device: Arc<dyn BlockDevice>,  // 块设备（例如硬盘或虚拟磁盘）引用
        total_blocks: u32,  // 文件系统的总块数
        inode_bitmap_blocks: u32,  // inode 位图所占块数
    ) -> Arc<Mutex<Self>> {  // 返回一个 Arc<Mutex<Self>>，即文件系统的共享可变引用
        // calculate block size of areas & create bitmaps
        let inode_bitmap = Bitmap::new(1, inode_bitmap_blocks as usize);  // 创建 inode 位图，标记 inode 的使用状态
        let inode_num = inode_bitmap.maximum();  // 获取可用的 inode 数量（位图中标记的最大值）

        // 计算 inode 区域的块数
        let inode_area_blocks =
            ((inode_num * core::mem::size_of::<DiskInode>() + BLOCK_SZ - 1) / BLOCK_SZ) as u32;
        let inode_total_blocks = inode_bitmap_blocks + inode_area_blocks;  // inode 区域的总块数

        // 计算数据区域的块数
        let data_total_blocks = total_blocks - 1 - inode_total_blocks;  // 总块数减去 inode 区域的块数
        let data_bitmap_blocks = (data_total_blocks + 4096) / 4097;  // 数据位图块数
        let data_area_blocks = data_total_blocks - data_bitmap_blocks;  // 数据区域块数

        // 创建数据位图
        let data_bitmap = Bitmap::new(
            (1 + inode_bitmap_blocks + inode_area_blocks) as usize,
            data_bitmap_blocks as usize,
        );

        // 构建 EasyFileSystem 实例
        let mut efs = Self {
            block_device: Arc::clone(&block_device),  // 克隆块设备引用
            inode_bitmap,  // 设置 inode 位图
            data_bitmap,  // 设置数据位图
            inode_area_start_block: 1 + inode_bitmap_blocks,  // inode 区域起始块
            data_area_start_block: 1 + inode_total_blocks + data_bitmap_blocks,  // 数据区域起始块
        };

        // clear all blocks: 清空所有块的内容
        for i in 0..total_blocks {  // 遍历所有块
            get_block_cache(
                i as usize,
                Arc::clone(&block_device)  // 获取块缓存
            )
                .lock()  // 获取锁，确保线程安全
                .modify(0, |data_block: &mut DataBlock| {  // 清空块内容
                    for byte in data_block.iter_mut() { *byte = 0; }
                });
        }

        // initialize SuperBlock: 初始化超级块
        get_block_cache(0, Arc::clone(&block_device))  // 获取超级块缓存
            .lock()  // 获取锁
            .modify(0, |super_block: &mut SuperBlock| {  // 设置超级块的初始化信息
                super_block.initialize(
                    total_blocks,
                    inode_bitmap_blocks,
                    inode_area_blocks,
                    data_bitmap_blocks,
                    data_area_blocks,
                );
            });

        // write back immediately: 立即写回到块设备

        // create a inode for root node "/": 为根节点“/”创建 inode
        assert_eq!(efs.alloc_inode(), 0);  // 分配第一个 inode，应该是根目录 inode
        let (root_inode_block_id, root_inode_offset) = efs.get_disk_inode_pos(0);  // 获取根 inode 的磁盘位置
        get_block_cache(
            root_inode_block_id as usize,
            Arc::clone(&block_device)  // 获取 inode 块的缓存
        )
            .lock()  // 获取锁
            .modify(root_inode_offset, |disk_inode: &mut DiskInode| {  // 设置根 inode 的类型
                disk_inode.initialize(DiskInodeType::Directory);  // 初始化为目录类型
            });

        // 返回一个 Arc<Mutex<Self>>，表示文件系统对象
        Arc::new(Mutex::new(efs))
    }
    /// Open a block device as a filesystem
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Arc<Mutex<Self>> {
        // read SuperBlock
        get_block_cache(0, Arc::clone(&block_device))
            .lock()
            .read(0, |super_block: &SuperBlock| {
                assert!(super_block.is_valid(), "Error loading EFS!");
                let inode_total_blocks =
                    super_block.inode_bitmap_blocks + super_block.inode_area_blocks;
                let efs = Self {
                    block_device,
                    inode_bitmap: Bitmap::new(1, super_block.inode_bitmap_blocks as usize),
                    data_bitmap: Bitmap::new(
                        (1 + inode_total_blocks) as usize,
                        super_block.data_bitmap_blocks as usize,
                    ),
                    inode_area_start_block: 1 + super_block.inode_bitmap_blocks,
                    data_area_start_block: 1 + inode_total_blocks + super_block.data_bitmap_blocks,
                };
                Arc::new(Mutex::new(efs))
            })
    }
    /// Get the root inode of the filesystem
    pub fn root_inode(efs: &Arc<Mutex<Self>>) -> Inode {
        let block_device = Arc::clone(&efs.lock().block_device);
        // acquire efs lock temporarily
        let (block_id, block_offset) = efs.lock().get_disk_inode_pos(0);
        // release efs lock
        Inode::new(block_id, block_offset, Arc::clone(efs), block_device)
    }
    /// Get inode by id
    pub fn get_disk_inode_pos(&self, inode_id: u32) -> (u32, usize) {
        let inode_size = core::mem::size_of::<DiskInode>();
        let inodes_per_block = (BLOCK_SZ / inode_size) as u32;
        let block_id = self.inode_area_start_block + inode_id / inodes_per_block;
        (
            block_id,
            (inode_id % inodes_per_block) as usize * inode_size,
        )
    }
    /// Get data block by id
    pub fn get_data_block_id(&self, data_block_id: u32) -> u32 {
        self.data_area_start_block + data_block_id
    }
    /// Allocate a new inode
    pub fn alloc_inode(&mut self) -> u32 {
        self.inode_bitmap.alloc(&self.block_device).unwrap() as u32
    }

    /// Allocate a data block
    pub fn alloc_data(&mut self) -> u32 {
        self.data_bitmap.alloc(&self.block_device).unwrap() as u32 + self.data_area_start_block
    }
    /// Deallocate a data block
    pub fn dealloc_data(&mut self, block_id: u32) {
        get_block_cache(block_id as usize, Arc::clone(&self.block_device))
            .lock()
            .modify(0, |data_block: &mut DataBlock| {
                data_block.iter_mut().for_each(|p| {
                    *p = 0;
                })
            });
        self.data_bitmap.dealloc(
            &self.block_device,
            (block_id - self.data_area_start_block) as usize,
        )
    }
}
