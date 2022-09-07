# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.


from avatar2 import Avatar, QemuTarget
from ..bp_handlers.bp_handler import BPHandler
from ..bp_handlers import intercepts
# from ..bp_handlers.generic.debug import IPythonShell
import logging
import struct
import binascii
from .. import hal_log, hal_config

log = logging.getLogger(__name__)
hal_log = hal_log.getHalLogger()


class AllocedMemory():
    def __init__(self, target, base_addr, size):
        self.target = target
        self.base_addr = base_addr
        self.size = size
        self.in_use = True
        #TODO add ability to set watchpoint for bounds checking

    def zero(self):
        zeros = "\x00"* self.size
        self.target.write_memory(self.base_addr, 1, zeros, raw=True)

    def alloc_portion(self, size):
        if size < self.size:
            new_alloc = AllocedMemory(self.target, self.base_addr, size)
            self.base_addr += size
            self.size -= size
            return new_alloc, self
        elif size == self.size:
            self.in_use = True
            return self, None
        else:
            raise ValueError("Trying to alloc %i bytes from chuck of size %i" %(size, self.size))

    def merge(self, block):
        '''
            Merges blocks with this one
        '''
        self.size += block.size
        self.base_addr = self.base_addr if self.base_addr <= block.base_addr else block.base_addr

class M68KQemuTarget(QemuTarget):
    '''
        Implements a QEMU target that has function args for use with
        halucinator.  Enables read/writing and returning from
        functions in a calling convention aware manner
    '''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.irq_base_addr = None
        self.init_halucinator_heap()
        self.calls_memory_blocks = {}  # Look up table of allocated memory
                                       # used to perform calls


    def read_string(self, addr, max_len=256):
        s = self.read_memory(addr, 1, max_len, raw=True)
        s = s.decode('latin-1')
        return s.split('\x00')[0]


    def dictify(self, ignore=None):
        if ignore is None:
            ignore = ['state', 'status', 'regs', 'protocols', 'log', 'avatar', 
                      'alloced_memory', 'free_memory', 'calls_memory_blocks']
        super().dictify(ignore)

    def init_halucinator_heap(self):
        '''
            Initializes the scratch memory in the target that halucinator 
            can use.  This requires that a 'halucinator' memory region
            exists.
        '''

        for mem_name, mem_data in self.avatar.config.memories.items():
            if mem_name == 'halucinator':
                heap = AllocedMemory(self, mem_data.base_addr, mem_data.size)
                heap.in_use = False
                self.alloced_memory = set() 
                self.free_memory = set()
                self.free_memory.add(heap)
                return

        raise ValueError("Memory region named 'halucinator required")

    def hal_alloc(self, size):
        
        if size % 4:
            size += 4 - (size % 4) # keep aligned on 4 byte boundary
        changed_block = None
        alloced_block = None
        free_block = None
        for block in self.free_memory:
            if not block.in_use and size <= block.size:
                alloced_block, free_block = block.alloc_portion(size)
                changed_block = block
                break
        
        self.free_memory.remove(changed_block)
        if free_block is not None:
            self.free_memory.add(free_block)
        if alloced_block is not None:
            self.alloced_memory.add(alloced_block)
        return alloced_block

    def hal_free(self, mem):
        mem.is_used = False
        self.alloced_memory.remove(mem)
        merged_block = None
        for free_block in self.free_memory:
            # See if previous block is contiguous with this one
            if block.base_addr + block.size ==  mem.base_addr:
                block.merge(mem)
                merged_block = block
                break
            elif mem.base_addr + mem.size == block.base_addr:
                block.merge(mem)
                merged_block = block
                break

        if merged_block is None:
            self.free_memory.add(mem)
        else:
            self.free_scratch_memory(merged_block)

    def get_arg(self, idx, call_conv=None, prefix=None):
        '''
            Gets the value for a function argument (zero indexed)

            :param idx  The argument index to return
            :param call_conv Calling convention (STACK or REG)
            :param prefix    Register prefix (a or d)
            :returns    Argument value
        '''
        if call_conv == "STACK":
            if idx >= 0:
                sp = self.read_register("sp")
                stack_addr = sp + idx * 4
                return self.read_memory(stack_addr, 4, 1)
            else:
                raise ValueError("Invalid arg index")
        if call_conv == "REG":
            if idx >= 0 and idx <= 7:
                return self.read_register("%s%i" % (idx, prefix))
            else:
                raise ValueError("Invalid arg index")

    def set_args(self, args, call_conv=None):
        '''
            Sets the value for a function argument (zero indexed)

            :param args:  Iterable of args to set
            :param call_conv: String denoting calling convention
        '''
        
        if call_conv == "STACK":
            sp = self.read_register("sp")
            for idx, value in enumerate(args[::-1]):
                sp -= 4
                self.write_memory(sp, 4, value)
            
            self.write_register('sp', sp)
    
        if call_conv == "REG":
            for idx, value in enumerate(args):
                print(type(args))
                self.write_register('d%i' % idx, value)
                raise NotImplementedError("Can't distinguish between address and data registersa") 

        return sp

    def get_ret_addr(self):
        '''
            Gets the return address for the function call

            :returns Return address of the function call
        '''
        sp = self.read_register("sp")
        ret_addr = self.read_memory(sp, 4, 1)
        sp += 4
        self.write_register("sp", sp)

        return ret_addr

    def set_ret_addr(self, ret_addr):
        '''
            Sets the return address for the function call
            :param ret_addr Value for return address
        '''
        sp = self.read_register("sp")
        ret_addr = self.read_memory(sp, 4, 1)
        sp -= 4
        self.write_memory(sp, 4, ret_addr)
        self.write_register("sp", sp)

    def execute_return(self, ret_value):
        if ret_value != None:
            # Puts ret value in d0
            # TODO balex: do I need to handle two return values? Or address returns
            # https://wiki.freepascal.org/m68k
            self.regs.d0 = ret_value & 0xFFFFFFFF #Truncate to 32 bits
        self.regs.pc = self.get_ret_addr() 


    def get_irq_base_addr(self):
        if self.irq_base_addr is not None:
            return self.irq_base_addr
        else:
            for mem_name, mem_data in self.avatar.config.memories.items():
                if mem_data.qemu_name == 'halucinator-irq':
                    self.irq_base_addr = mem_data.base_addr
                    return self.irq_base_addr
        raise(TypeError("No Interrupt Controller found, include a memory with qemu_name: halucinator-irq"))

    def irq_set_qmp(self, irq_num=1):
        '''
            Set interrupt using qmp. 
            DO NOT execute in context of a bp handler, use irq_set_bp instead

            :param irq_num:  The irq number to trigger
        '''
        addr = self.get_irq_base_addr() + irq_num
        self.protocols.monitor.execute_command("pmemwrite",
            args={"pmem_addr":addr, "data_buff": '01'})

    def irq_clear_qmp(self, irq_num=1):
        '''
            Clear interrupt using qmp.  
            DO NOT execute in context of a bp handler, use irq_clear_bp

            :param irq_num:  The irq number to trigger
        '''

        addr = self.get_irq_base_addr() + irq_num
        self.protocols.monitor.execute_command("pmemwrite",
            args={"pmem_addr":addr, "data_buff": "00"})

    def irq_set_bp(self, irq_num=1):

        addr = self.get_irq_base_addr() + irq_num
        self.write_memory(addr,1,1)

    def irq_clear_bp(self, irq_num):
        addr = self.get_irq_base_addr() + irq_num
        log.debug("Clearing IRQ BP")
        self.write_memory(addr,1,0)

    def irq_pulse(self, irq_num=1, cpu=0):
        self.protocols.monitor.execute_command("avatar-set-irq", 
            args={"cpu_num":cpu, "irq_num": irq_num, "value":3})

    def get_symbol_name(self, addr):
        """
        Get the symbol for an address

        :param addr:    The name of a symbol whose address is wanted
        :returns:         (Symbol name on success else None
        """

        return self.avatar.config.get_symbol_name(addr)

    def set_bp(self, addr, handler_cls, handler, run_once=False):
        '''
            Adds a break point setting the class and method to handler it.

            :param addr:    Address of break point
            :param handler_cls:   Instance or import string for BPHandler class that 
                            has handler for this bp
            :param handler: String identifing the method in handler_class to 
                            handle the bp (ie. value in @bp_handler decorator)
            :param run_once:  Bool, BP should only trigger once
        '''
        if type(handler_cls) == str:
            cls_name = handler_cls
        else:
            cls_name = type(handler_cls).__module__ + "." + type(handler_cls).__qualname__
        config = {'cls': cls_name, 'run_once': run_once, 'function': handler,
                    'addr': addr}
        intercept_config = hal_config.HalInterceptConfig(__file__, **config)
        intercepts.register_bp_handler(self, intercept_config)

    def call_varg(self, ret_bp_handler, callee, *args):
        raise NotImplementedError("Calling Varg functions not supported")

    def call(self, callee, args=None, bp_handler_cls=None, ret_bp_handler=None,
            call_conv=None, debug=False):
        '''
            Calls a function in the binary and returning to ret_bp_handler.
            Using this without side effects requires conforming to calling
            convention (e.g. R0-R3 have parameters and are scratch registers 
            (callee save), if other registers are modified they need to be 
            saved and restored)

            :param callee:   Address or name of function to be called
            :param args:     An iterable containing the args to called function
            :param bp_handler_cls:  Instance of class containing next bp_handler
                                    or string for that class
            :param ret_bp_handler:  String of used in @bp_handler to identify 
                                    method to use for return bp_handler
            :param call_conv:       Calling convention for function to be called,
                                    currently either "STACK" or "REG"
        '''
        
        if type(callee) == int:
            addr = callee
        else:
            addr = self.avatar.config.get_addr_for_symbol(callee)

        if addr == None:
            raise ValueError("Making call to %s.  Address for not found for: %s"
                             % (callee,callee))

        key = (bp_handler_cls.__class__, ret_bp_handler, addr, len(args))
        self.push_lr()
        new_sp = self.set_args(args)

        # If first time seeing this inject instructions to execute
        if key not in self.calls_memory_blocks:
            instrs = deque()
            # Build instructions in reverse order so we know offset to end
            # Where we store the address of the function to be called
           
            instrs.append(struct.pack('<I', addr))  # Address of callee
            instrs.append(struct.pack('<I, 0x2e97'))  # move.l (sp)+, pc      

            # import IPython; IPython.embed()
            offset = len(b''.join(instrs)) #PC is two instructions ahead so need to calc offset
                                          # two instructions before its execution 
    
            # Clean up stack based registers if needed
            if call_conv == "STACK":
                stack_var_size = (len(args)) * 4
                instrs.append(struct.pack('<I', 0x048f00000000 + stack_var_size)) # addi #(stack_var_size), sp
                offset += 6

            instrs.append(struct.pack('<I', 0x4e90)) # jsr (a0)
            instrs.append(struct.pack('<I', 0x207a0000 + offset)) # move.l ((offset), pc), a0 
            instructions = b''.join(instrs)
            mem = self.hal_alloc(len(instructions))
            
            bytes_written = 0
            while instrs:
                bytearr = instrs.pop()
                inst_addr = mem.base_addr + bytes_written
                self.write_memory(inst_addr, 1, 
                                    bytearr, len(bytearr), raw=True)
                
                log.debug("Injected %#x:  %s" % (inst_addr, 
                    binascii.hexlify(bytearr)))

                # Set break point before this function returns so new BP handler
                # can do its stuff if set
                if len(instrs) == 1: # last instruction written is addr
                    if bp_handler_cls is not None and ret_bp_handler is not None:
                        self.set_bp(inst_addr, bp_handler_cls, ret_bp_handler)
                bytes_written += len(bytearr)
        else:
            mem = self.calls_memory_blocks[key]
        
        if debug:
            self.set_bp(mem.base_addr, "halucinator.bp_handlers.generic.debug.IPythonShell", 'shell')

        self.regs.pc = mem.base_addr 
        return False, None
