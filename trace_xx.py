import ida_idaapi
import ida_dbg
import ida_auto
import idautils
import ida_kernwin
import ida_idd

def set_breakpoint(addr):
    ida_dbg.add_bpt(addr)

def get_all_modules(module):
    for i in idautils.Modules():
        print(i.name,i.base,i.size)

def my_suspend_thread():
    # 获取当前线程id
    current_tid = ida_dbg.get_current_thread()
    # 获取线程数量
    count = ida_dbg.get_thread_qty()
    for i in range(count):
        tid = ida_dbg.getn_thread(i)
        if tid != current_tid:
            ida_dbg.suspend_thread(tid)

def my_resume_thread():
    # 获取当前线程id
    current_tid = ida_dbg.get_current_thread()
    # 获取线程数量
    count = ida_dbg.get_thread_qty()
    for i in range(count):
        tid = ida_dbg.getn_thread(i)
        if tid != current_tid:
            ida_dbg.resume_thread(tid)

def my_get_reg_value(register):
    rv = ida_idd.regval_t()
    ida_dbg.get_reg_val(register, rv)
    current_addr = rv.ival
    return current_addr

class MyDebugger(ida_dbg.DBG_Hooks):

    """ Own debug hook class that implementd the callback functions """
    def __init__(self,base_addr,base_size,start_addr,end_addr):
        ida_dbg.DBG_Hooks.__init__(self)
        print('MyDebugger init')
        self.base_addr = base_addr
        self.base_size = base_size
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.traces = 0
        self.line_trace = 0
        self.trace_lr = 0
        self.trace_step_into_count = 0
        self.trace_step_into_size = 1
        self.trace_total_size = 300000
        self.trace_size = 0

    def log(self,log):
        print('>>> %s' % log)

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self.log("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
    
    def dbg_process_exit(self, pid, tid, ea, code):
        self.log("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

    def dbg_library_unload(self, pid, tid, ea, info):
        self.log("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self.log("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
    
    def dbg_process_detach(self, pid, tid, ea):
        self.log("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        self.log("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))

    def dbg_bpt(self, tid, ea):
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        self.log("Break point at 0x%x pid=%d" % (ea, tid))
        self.line_trace = 1
        if (ea == self.start_addr):
            self.log("suspend all thread")
            my_suspend_thread()
            ida_dbg.request_clear_trace()
            ida_dbg.run_requests()
            ida_dbg.enable_insn_trace(True)
            ida_dbg.enable_step_trace(True)
        
        if (ea > self.end_addr):
            ida_dbg.enable_insn_trace(False)
            ida_dbg.enable_step_trace(False)
            ida_dbg.suspend_process()
            self.log("resume all thread")
            my_resume_thread()
        return 1
    
    def dbg_suspend_process(self):
        self.log("Process suspended")

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
         # return values:
        #   -1 - to display an exception warning dialog
        #        if the process is suspended.
        #   0  - to never display an exception warning dialog.
        #   1  - to always display an exception warning dialog.
        self.log("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            pid, tid, ea, exc_code & ida_idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
        return 1

    def dbg_trace(self, tid, ea):
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it

        # if ea < self.base_addr or ea > (self.base_addr + self.base_size):
        #     raise Exception(
        #         "Received a trace callback for an address outside!"
        #     )
        self.log("Trace tid=%d ea=0x%x" % (tid, ea))
        if self.line_trace:
            target_so = False
            if self.base_addr <= ea <= (self.base_addr + self.base_size):
                target_so = True
            
            if not target_so:
                if (self.trace_lr != 0) and (self.trace_step_into_count < self.trace_step_into_size):
                    self.trace_step_into_count += 1
                    return 0

                if (self.trace_lr != 0) and (self.trace_step_into_count == self.trace_step_into_size):
                    ida_dbg.enable_insn_trace(False)
                    ida_dbg.enable_step_trace(False)
                    ida_dbg.suspend_process()
                    if self.trace_size > self.trace_total_size:
                        self.trace_size = 0
                        ida_dbg.request_clear_trace()
                        ida_dbg.run_requests()

                    ida_dbg.request_run_to(self.trace_lr & 0xFFFFFFFE)
                    ida_dbg.run_requests()
                    self.trace_lr = 0
                    self.trace_step_into_count = 0
                    return 0

                if self.trace_lr == 0:
                    self.trace_lr = my_get_reg_value("LR")
        
        self.traces += 1
        return 0

    def dbg_step_into(self):
        self.log("Step into")
        self.dbg_step_over()

    def dbg_run_to(self, pid, tid=0, ea=0):
        self.log("Runto: tid=%d, ea=%x" % (tid, ea))
        ida_dbg.enable_insn_trace(True)
        ida_dbg.enable_step_trace(True)
        ida_dbg.request_continue_process()
        ida_dbg.run_requests()

    def dbg_process_exit(self, pid, tid, ea, code):
        self.log("process exited with %d" % code)
        self.log("traced %d instructions" % self.traces)
        return 0


def start_hook(base_addr,base_size,start_addr,end_addr):
    global debugger
    debugger = MyDebugger(base_addr,base_size,start_addr,end_addr)
    debugger.hook()

def stop_hook():
    # Remove an existing debug hook
    try:
        if debugger:
            print("Removing previous hook ...")
            debugger.unhook()
    except:
        pass


def main():

    target = 'libnative-lib.so'
    start_addr = 0x8D60
    end_addr = 0x8DC0
    base_addr = 0
    base_size = 0

    # 找到要trace的模块，然后设置起始断点
    for i in idautils.Modules():
        if (i.name[i.name.rfind('/') + 1:]) == target:
            print(i.name,i.base,i.size)
            base_addr = i.base
            base_size = i.size
            set_breakpoint(base_addr + start_addr)
            set_breakpoint(base_addr + end_addr)
            ida_auto.auto_make_code(base_addr + start_addr)
            ida_kernwin.jumpto(base_addr + start_addr) # ida界面跳到指定起始位置

            # trace 设置
            # ida_dbg.enable_step_trace(True)
            # ida_dbg.set_step_trace_options(ida_idaapi.ST_OVER_DEBUG_SEG | ida_idaapi.ST_OVER_LIB_FUNC)
            # print("Running to %s" % base_addr + start_addr)
            # ida_dbg.run_to(base_addr + start_addr)
    start_hook(base_addr,base_size,base_addr + start_addr,base_addr + end_addr)
   

if __name__ == '__main__':
    main()