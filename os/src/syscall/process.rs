//! Process management syscalls
//!
use alloc::{sync::Arc, vec, vec::Vec};

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE, TRAP_CONTEXT_BASE},
    fs::{open_file, OpenFlags, Stdin, Stdout},
    mm::{
        translate_va_to_pa, translated_refmut, translated_str, MapPermission, MemorySet, PageTable,
        StepByOne, VirtAddr, KERNEL_SPACE,
    },
    sync::UPSafeCell,
    task::{
        add_task, current_task, current_user_token, drop_frame_area, exit_current_and_run_next,
        get_current_task_time, get_syscall_times, insert_framed_area, kstack_alloc, pid_alloc,
        suspend_current_and_run_next, TaskContext, TaskControlBlock, TaskControlBlockInner,
        TaskStatus, BIG_STRIDE,
    },
    timer::get_time_us,
    trap::{trap_handler, TrapContext},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    //trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        task.exec(all_data.as_slice());
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel:pid[{}] sys_get_time", current_task().unwrap().pid.0);
    let us = get_time_us();
    let ts = translate_va_to_pa(current_user_token(), ts as usize) as *mut TimeVal;
    unsafe {
        *ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!(
        "kernel:pid[{}] sys_task_info",
        current_task().unwrap().pid.0
    );
    let ti = translate_va_to_pa(current_user_token(), ti as usize) as *mut TaskInfo;
    unsafe {
        (*ti).status = TaskStatus::Running;
        (*ti).syscall_times = get_syscall_times();
        (*ti).time = get_current_task_time();
    }
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel:pid[{}] sys_mmap", current_task().unwrap().pid.0);
    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);
    if start_va.page_offset() != 0 || port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }
    let mut start_vpn = start_va.floor();
    let pt = PageTable::from_token(current_user_token());
    for _ in 0..((len + PAGE_SIZE - 1) / PAGE_SIZE) {
        match pt.translate(start_vpn) {
            Some(pte) => {
                if pte.is_valid() {
                    return -1;
                }
            }
            None => {}
        }
        start_vpn.step();
    }
    let mut permissions = MapPermission::empty();
    permissions.set(MapPermission::R, port & 0x1 != 0);
    permissions.set(MapPermission::W, port & 0x2 != 0);
    permissions.set(MapPermission::X, port & 0x4 != 0);
    permissions.set(MapPermission::U, true);
    insert_framed_area(start_va, end_va, permissions);
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_munmap", current_task().unwrap().pid.0);
    let start_va = VirtAddr::from(start);
    if start_va.page_offset() != 0 {
        return -1;
    }
    let mut start_vpn = start_va.floor();
    let end_va = VirtAddr::from(start + len);
    let pt = PageTable::from_token(current_user_token());
    for _ in 0..((len + PAGE_SIZE - 1) / PAGE_SIZE) {
        match pt.translate(start_vpn) {
            Some(pte) => {
                if !pte.is_valid() {
                    return -1;
                }
            }
            None => return -1,
        }
        start_vpn.step();
    }
    drop_frame_area(start_va, end_va);
    0
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_spawn", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let parent_task = current_task().unwrap();
        let mut parent_inner = parent_task.inner_exclusive_access();
        let (memory_set, user_sp, entry_point) =
            MemorySet::from_elf(app_inode.read_all().as_slice());
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();
        let pid_handle = pid_alloc();
        let pid = pid_handle.0;
        let kernel_stack = kstack_alloc();
        let kernel_stack_top = kernel_stack.get_top();
        let new_task = Arc::new(TaskControlBlock {
            pid: pid_handle,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    trap_cx_ppn,
                    base_size: 0,
                    task_cx: TaskContext::goto_trap_return(kernel_stack_top),
                    task_status: TaskStatus::Ready,
                    memory_set,
                    parent: Some(Arc::downgrade(&parent_task)),
                    children: Vec::new(),
                    exit_code: 0,
                    heap_bottom: user_sp,
                    program_brk: user_sp,
                    task_syscall_times: [0; MAX_SYSCALL_NUM],
                    task_time: 0,
                    stride: 0,
                    pass: BIG_STRIDE / 16,
                    priority: 16,
                    fd_table: vec![
                        // 0 -> stdin
                        Some(Arc::new(Stdin)),
                        // 1 -> stdout
                        Some(Arc::new(Stdout)),
                        // 2 -> stderr
                        Some(Arc::new(Stdout)),
                    ],
                })
            },
        });
        parent_inner.children.push(new_task.clone());
        {
            let new_task_inner = new_task.inner_exclusive_access();
            let trap_cx = TrapContext::app_init_context(
                entry_point,
                user_sp,
                KERNEL_SPACE.exclusive_access().token(),
                new_task.kernel_stack.get_top(),
                trap_handler as usize,
            );
            *new_task_inner.get_trap_cx() = trap_cx;
        }
        add_task(new_task);
        pid as isize
    } else {
        -1
    }
    // i can has fork + exec?
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority",
        current_task().unwrap().pid.0
    );
    if prio >= 2 {
        let current_task = current_task().unwrap();
        let mut inner = current_task.inner_exclusive_access();
        inner.priority = prio;
        inner.pass = BIG_STRIDE / prio;
        prio
    } else {
        -1
    }
}
