import re
import sys
from typing import List, Tuple, Set, Optional


def eprint(*args):
    print(*args, file=sys.stderr)
    with open('/tmp/py-as.log', 'a') as f:
        print(*args, file=f)


def percent(a, b):
    return 100 * a / max(b, 1)


def uncomment(x: str) -> str:
    """
    Remove a comment from an assembly instruction.  " mov a, b # c" => "mov a, b"
    """
    if '#' in x:
        x = x[:x.index('#')]
    return x.strip()


def uncomment_r(x: str) -> str:
    """
    Remove a comment from an assembly instruction, without lstrip.  " mov a, b # c" => " mov a, b"
    """
    if '#' in x:
        x = x[:x.index('#')]
    return x.rstrip()


class AssemblyFile:
    REGISTER_D_TO_Q = {
        '%eax': '%rax',
        '%ebx': '%rbx',
        '%ecx': '%rcx',
        '%edx': '%rdx',
        '%esi': '%rsi',
        '%edi': '%rdi',
        '%ebp': '%rbp',
        '%esp': '%rsp',
        '%r8d': '%r8',
        '%r9d': '%r9',
        '%r10d': '%r10',
        '%r11d': '%r11',
        '%r12d': '%r12',
        '%r13d': '%r13',
        '%r14d': '%r14',
        '%r15d': '%r15',
    }
    REGISTER_Q_TO_D = {v: k for k, v in REGISTER_D_TO_Q.items()}

    def __init__(self, filename: str):
        self.filename = filename
        with open(filename, 'r') as f:
            self.lines: List[str] = f.read().split('\n')
        self.rewriters: List[AssemblyRewriter] = []
        self.added_lines = 0
        self.is_gnu_assembly = any(line.startswith('\t.ident\t"GCC:') for line in self.lines)

    def save(self):
        with open(self.filename, 'w') as f:
            f.write('\n'.join(self.lines))

    def dump(self):
        print('\n'.join(self.lines))

    def is_indirect_tailcall(self, pos: int) -> bool:
        if self.lines[pos].endswith('# TAILCALL'):
            return True
        if self.lines[pos].startswith('\tjmp\t'):
            if self.lines[pos][5] == '*' and self.is_gnu_assembly:
                # jmp	*%rax    can be from GNU's jumptables
                return uncomment(self.lines[pos+1]) != '.section\t.rodata'
            else:
                return self.lines[pos][5] != '.'
        return False

    def rewrite(self):
        i = 0
        while i < len(self.lines):
            if self.lines[i] == '\tretq' or self.lines[i] == '\tret':
                self.added_lines = 0
                for r in self.rewriters:
                    if r.instrument_function_return(i):
                        break
                i += self.added_lines
            elif (self.lines[i].startswith('\tjmp\t') or self.lines[i].startswith('\tjmpq\t')) and self.is_indirect_tailcall(i):
                self.added_lines = 0
                for r in self.rewriters:
                    if r.instrument_function_tailcall(i):
                        break
                i += self.added_lines
            elif self.lines[i] == '\t.cfi_startproc':
                self.added_lines = 0
                for r in self.rewriters:
                    if r.instrument_function_begin(i):
                        break
                i += self.added_lines
            i += 1
        for r in self.rewriters:
            r.instrument_done()

    def add_before(self, i: int, instructions: List[str]):
        for n, instruction in enumerate(instructions):
            self.lines.insert(i + n, instruction)
        self.added_lines += len(instructions)

    def instruction_can_be_ignored(self, line: str, stack_offset: int) -> bool:
        if line.startswith('\tmovsd') or line.startswith('\tmovaps') or line.startswith('\tmovups') or line.startswith('\tmovupd') or line.startswith('\tmovdqu') or line.startswith('\tmovapd'):
            register1, register2 = uncomment(line).split('\t', 1)[1].split(', ', 1)
            register1 = register1.strip()
            register2 = register2.strip()
            if register2.endswith('(%rsp)') and register1.startswith('%xmm'):
                # movq	%rsi, 8(%rsp) # "safe" memory write
                number = int(register2[:-6] if len(register2) > 6 else 0)
                if number != -stack_offset:
                    return True
            if register2.startswith('%xmm'):
                return True
            return False
        if line.startswith('\tmovq') or line.startswith('\tmovslq') or line.startswith('\tmovabsq'):
            ins, register = uncomment(line).rsplit(',', 1)
            register = register.strip()
            if register.endswith('(%rsp)'):
                # movq	%rsi, 8(%rsp) # "safe" memory write
                number = int(register[:-6] if len(register) > 6 else 0)
                if number != -stack_offset:
                    return True
        return False

    def find_free_registers_before(self, i: int, num: int) -> Tuple[int, Set[str], int]:
        """
        :return: new position, list of free registers, stack offset

        stack offset: rsp@new - rsp@old
        """
        registers = set()
        stack_offset = 0
        while len(registers) < num:
            if self.lines[i - 1].lstrip().startswith('#'):
                i -= 1
            elif self.lines[i - 1].startswith('\t.cfi_def_') or self.lines[i-1].startswith('\t.cfi_remember_'):
                i -= 1
            elif self.lines[i - 1].startswith('\tpopq\t'):
                i -= 1
                registers.add(self.lines[i][6:])
                stack_offset -= 8
            elif self.lines[i - 1].startswith('\txorl\t'):
                i -= 1
                r1, r2 = uncomment(self.lines[i][6:]).split(',', 1)
                if r1.strip() == r2.strip():
                    registers.add(self.REGISTER_D_TO_Q[r1.strip()])
                else:
                    return i, registers, stack_offset
            elif self.lines[i - 1].startswith('\taddq\t$'):
                i -= 1
                off, register = uncomment(self.lines[i][7:]).split(',', 1)
                if register.strip() != '%rsp':
                    return i, registers, stack_offset
                stack_offset -= int(off)
            elif self.lines[i-1].startswith('\tleaq') or self.lines[i-1].startswith('\tmovq') or self.lines[i-1].startswith('\tmovslq') or self.lines[i-1].startswith('\tmovabsq') :
                ins, register = uncomment(self.lines[i - 1]).rsplit(',', 1)
                register = register.strip()
                if register.endswith('(%rsp)'):
                    # movq	%rsi, 8(%rsp) # "safe" memory write
                    number = int(register[:-6] if len(register) > 6 else 0)
                    if number != -stack_offset:
                        i -= 1
                        continue
                if register[0] != '%' or register in ins or register not in self.REGISTER_Q_TO_D or self.REGISTER_Q_TO_D[register] in ins or register == '%rsp':
                    return i, registers, stack_offset
                registers.add(register)
                # TODO remove src registers from set if len >1
                i -= 1
            elif self.instruction_can_be_ignored(self.lines[i - 1], stack_offset):
                i -= 1
            else:
                return i, registers, stack_offset
        return i, registers, stack_offset

    def find_free_register_after(self, i: int) -> Tuple[int, Optional[str], int]:
        """
        :return: new position, one free register, stack offset

        stack offset: rsp@new - rsp@old
        """
        stack_offset = 0
        while True:
            if self.lines[i+1].lstrip().startswith('#'):
                i += 1
            elif self.lines[i+1].startswith('\t.cfi_def_') or self.lines[i+1].startswith('\t.cfi_offset') or self.lines[i+1].startswith('\t.cfi_personality') or self.lines[i+1].startswith('\t.cfi_lsda'):
                i += 1
            elif self.lines[i+1].startswith('\tpushq'):
                i += 1
                stack_offset -= 8
            elif self.lines[i+1].startswith('\tsubq\t$'):
                i += 1
                off, register = uncomment(self.lines[i][7:]).split(',', 1)
                if '#' in register:
                    register = register.split('#')[0]
                if register.strip() != '%rsp':
                    return i, None, stack_offset
                stack_offset -= int(off)
            elif self.lines[i+1].startswith('\tmovl'):
                ins, register = uncomment(self.lines[i + 1]).split(',', 1)
                register = register.strip()
                if register.endswith('(%rsp)'):
                    # movl	..., 8(%rsp) # "safe" memory write
                    number = int(register[:-6] if len(register) > 6 else 0)
                    if number != -stack_offset:
                        i += 1
                        continue
                if register[0] != '%' or register in ins or self.REGISTER_D_TO_Q[register] in ins:
                    return i, None, stack_offset
                register = self.REGISTER_D_TO_Q[register]
                return i, register, stack_offset
            elif self.lines[i+1].startswith('\txorl'):
                register1, register2 = uncomment(self.lines[i + 1]).split('\t', 1)[1].split(',', 1)
                register1 = register1.strip()
                register2 = register2.strip()
                if register1 == register2 and register1 in self.REGISTER_D_TO_Q:
                    return i, self.REGISTER_D_TO_Q[register1], stack_offset
                return i, None, stack_offset
            elif self.lines[i+1].startswith('\tleaq') or self.lines[i+1].startswith('\tmovq') or self.lines[i+1].startswith('\tmovslq') or self.lines[i+1].startswith('\tmovabsq') :
                ins, register = uncomment(self.lines[i + 1]).rsplit(',', 1)
                register = register.strip()
                if register.endswith('(%rsp)'):
                    # movq	%rsi, 8(%rsp) # "safe" memory write
                    number = int(register[:-6] if len(register) > 6 else 0)
                    if number != -stack_offset:
                        i += 1
                        continue
                if register[0] != '%' or register in ins or register not in self.REGISTER_Q_TO_D or self.REGISTER_Q_TO_D[register] in ins:
                    return i, None, stack_offset
                return i, register, stack_offset
            elif self.instruction_can_be_ignored(self.lines[i + 1], stack_offset):
                i += 1
            else:
                return i, None, stack_offset


class AssemblyRewriter:
    def __init__(self, asm: AssemblyFile):
        self.asm = asm

    def instrument_function_begin(self, pos: int) -> Optional[bool]:
        pass

    def instrument_function_return(self, pos: int) -> Optional[bool]:
        pass

    def instrument_function_tailcall(self, pos: int) -> Optional[bool]:
        # eprint('TAIL CALL', self.asm.lines[pos])
        return self.instrument_function_return(pos)

    def instrument_done(self):
        pass

    def get_statistics(self) -> List[int]:
        return []


class ShadowStackRewriter(AssemblyRewriter):
    def __init__(self, asm: AssemblyFile):
        super().__init__(asm)
        self.count_begin = 0
        self.count_begin_fast = 0
        self.count_end = 0
        self.count_end_fast = 0
        self.offset = -0x70000000
        self.v2 = True

    def instrument_function_begin(self, pos: int):
        self.count_begin += 1

        new_pos, register, stack_offset = self.asm.find_free_register_after(pos)
        if register:
            self.asm.add_before(new_pos + 1, [
                f'\tmovq {-stack_offset}(%rsp), {register}',
                f'\tmovq {register}, {hex(self.offset - stack_offset)}(%rsp)'
            ])
            self.count_begin_fast += 1
        else:
            if self.v2:
                self.asm.add_before(pos + 1, [
                    f'popq {hex(self.offset-8)}(%rsp)',
                    'subq $8, %rsp'
                ])
            else:
                self.asm.add_before(pos + 1, [
                    'movq %r11, -8(%rsp)',
                    '\tmovq (%rsp), %r11',
                    f'\tmovq %r11, {hex(self.offset)}(%rsp)',
                    'movq -8(%rsp), %r11',
                ])

    def instrument_function_return(self, pos: int):
        self.count_end += 1

        new_pos, registers, stack_offset = self.asm.find_free_registers_before(pos, 1)
        if len(registers) >= 1:
            reg = list(registers)[0]
            self.asm.add_before(new_pos, [
                f'\tmovq {-stack_offset}(%rsp), {reg}',
                f'\tcmp {reg}, {hex(self.offset - stack_offset)}(%rsp)',
                f'\tjne .shadowstack_error_{pos}'
            ])
            self.asm.add_before(pos + 4, [
                f'.shadowstack_error_{pos}:',
                'ud2'
            ])
            self.count_end_fast += 1
        else:
            if self.v2:
                self.asm.add_before(pos, [
                    'pushq %r11',
                    '\tmovq 8(%rsp), %r11',
                    f'\tcmp %r11, {hex(self.offset + 8)}(%rsp)',
                    f'\tjne .shadowstack_error_{pos}',
                    'popq %r11',
                ])
            else:
                self.asm.add_before(pos, [
                    'movq %r11, -8(%rsp)',
                    '\tmovq (%rsp), %r11',
                    f'\tcmp %r11, {hex(self.offset)}(%rsp)',
                    f'\tjne .shadowstack_error_{pos}',
                    'movq -8(%rsp), %r11',
                ])
            self.asm.add_before(pos + 6, [
                f'.shadowstack_error_{pos}:',
                'ud2'
            ])

    def instrument_done(self):
        eprint(f'Instrumented {self.count_begin} function begins ({self.count_begin_fast} fast: {percent(self.count_begin_fast, self.count_begin):.1f}%)')
        eprint(f'Instrumented {self.count_end} function ends   ({self.count_end_fast} fast: {percent(self.count_end_fast, self.count_end):.1f}%)')

    def get_statistics(self) -> List[int]:
        return [self.count_begin, self.count_begin_fast, self.count_end, self.count_end_fast]


class RipXoringRewriter(AssemblyRewriter):
    def __init__(self, asm: AssemblyFile):
        super().__init__(asm)
        self.count_begin = 0
        self.count_begin_fast = 0
        self.count_end = 0
        self.count_end_fast = 0
        self.constant = '%fs:0x28'
        # self.constant = '$0x10000000000000'

    def instrument_function_begin(self, pos: int):
        self.count_begin += 1

        new_pos, register, stack_offset = self.asm.find_free_register_after(pos)
        if register:
            self.asm.add_before(new_pos + 1, [
                f'\tmovq {self.constant}, {register}',
                f'\txorq {register}, {-stack_offset}(%rsp)',
            ])
            self.count_begin_fast += 1
        else:
            self.asm.add_before(pos + 1, [
                '\tmovq %r11, -8(%rsp)',
                f'\tmovq {self.constant}, %r11',
                '\txorq %r11, 0(%rsp)',
                '\tmovq -8(%rsp), %r11',
            ])

    def instrument_function_return(self, pos: int):
        self.count_end += 1

        new_pos, registers, stack_offset = self.asm.find_free_registers_before(pos, 1)
        if len(registers) >= 1:
            register = list(registers)[0]
            self.asm.add_before(new_pos, [
                f'\tmovq {self.constant}, {register}',
                f'\txorq {register}, {-stack_offset}(%rsp)',
            ])
            self.count_end_fast += 1
        else:
            self.asm.add_before(pos, [
                '\tmovq %r11, -8(%rsp)',
                f'\tmovq {self.constant}, %r11',
                '\txorq %r11, 0(%rsp)',
                '\tmovq -8(%rsp), %r11',
            ])

    def instrument_done(self):
        eprint(f'Instrumented {self.count_begin} function begins ({self.count_begin_fast} fast: {percent(self.count_begin_fast, self.count_begin):.1f}%)')
        eprint(f'Instrumented {self.count_end} function ends   ({self.count_end_fast} fast: {percent(self.count_end_fast, self.count_end):.1f}%)')

    def get_statistics(self) -> List[int]:
        return [self.count_begin, self.count_begin_fast, self.count_end, self.count_end_fast]


class MemorySafeFunctionFilter(AssemblyRewriter):
    def __init__(self, asm: AssemblyFile):
        super().__init__(asm)
        self.is_memory_safe = False
        self.memory_safe_until = -1
        self.functions_safe = 0
        self.functions_unsafe = 0

    def is_function_memory_safe(self, pos: int) -> bool:
        pos += 1
        while pos < len(self.asm.lines):
            line = uncomment_r(self.asm.lines[pos]).rstrip()
            # is this the start of a new function?
            if line == '\t.cfi_startproc':
                return True
            if len(line) > 0 and line[0] != '.' and line[0] != '\t' and re.match(r'^\w+:$', line) and 'GCC_except_table' not in line:
                return True
            # is this an instruction?
            if line.startswith('\t') and not line.startswith('\t.'):
                # is it memory-safe?
                ins, args = re.split(r'\s', line[1:]+' ', maxsplit=1)
                if self.is_memory_unsafe_instruction(ins, args.strip()):
                    # print('UNSAFE:', line)
                    return False
            pos += 1
        return True

    @staticmethod
    def is_memory_unsafe_instruction(ins: str, args: str) -> bool:
        # some instructions are always safe or unsafe
        if ins == 'lea' or ins == 'leaq' or ins.startswith('cmp') or ins.startswith('test'):
            return False
        if ins.startswith('call') or ins == 'syscall' or ins.startswith('stos'):
            return True
        # we consider jumps safe, because they are *affected by* memory corruptions, but don't *trigger* one:
        if ins.startswith('jmp'):
            return False
        # stuff not supported so far
        if ins.startswith('rep'):
            return True
        # check the arguments
        if not args:
            return False
        arguments = args.split(', ')
        for arg in arguments:
            if arg.count('(') != arg.count(')'):
                raise Exception('Can not parse: ' + repr(ins) + ' ' + repr(args))
        arg = arguments[-1]
        if '(' not in arg or arg.endswith('(%rip)'):
            return False
        if re.match(r'^-?\d*\(%rsp\)$', arg) or re.match(r'^.L\w+$', arg):
            return False
        # special case: "movq $0, (...)" - it's not possible to write a meaningful value here
        if ins == 'movq' and arguments[0] == '$0':
            return False
        return True

    def instrument_function_begin(self, pos: int) -> Optional[bool]:
        if self.is_function_memory_safe(pos):
            self.is_memory_safe = True
            self.functions_safe += 1
        else:
            self.is_memory_safe = False
            self.functions_unsafe += 1
        return self.is_memory_safe

    def instrument_function_return(self, pos: int) -> Optional[bool]:
        # skip instrumentation if last
        return self.is_memory_safe

    def instrument_done(self):
        eprint(f'Safe functions:    {self.functions_safe:4d} ({self.functions_safe*100.0 / max(1, self.functions_safe + self.functions_unsafe):.1f}%)')
        eprint(f'Unsafe functions:  {self.functions_unsafe:4d}')

    def get_statistics(self) -> List[int]:
        return [self.functions_safe, self.functions_unsafe]


class CanaryCountRewriter(AssemblyRewriter):
    def __init__(self, asm: AssemblyFile):
        super().__init__(asm)
        self.function_begins = 0
        self.function_begins_with_scratch = 0
        self.function_returns = 0
        self.function_returns_with_scratch = 0
        self.function_tailcalls = 0
        self.function_tailcalls_with_scratch = 0
        self.function_begins_with_canaries = 0
        self.function_returns_with_canaries = 0
        self.verbose = False

    def instrument_function_begin(self, pos: int) -> Optional[bool]:
        self.function_begins += 1
        new_pos, register, stack_offset = self.asm.find_free_register_after(pos)
        if register:
            self.function_begins_with_scratch += 1
        elif self.verbose:
            print('NO SCRATCH', pos, self.asm.lines[pos])
        if self.find_canary(pos + 1, 1):
            self.function_begins_with_canaries += 1
        elif self.verbose:
            print('NO CANARY', pos, self.asm.lines[pos])
        return False

    def instrument_function_return(self, pos: int) -> Optional[bool]:
        self.function_returns += 1
        new_pos, registers, stack_offset = self.asm.find_free_registers_before(pos, 1)
        if len(registers):
            self.function_returns_with_scratch += 1
        elif self.verbose:
            print('NO SCRATCH', pos, self.asm.lines[pos])
        if self.find_canary(pos-1, -1):
            self.function_returns_with_canaries += 1
        elif self.verbose:
            print('NO CANARY', pos, self.asm.lines[pos])
        return False

    def instrument_function_tailcall(self, pos: int) -> Optional[bool]:
        self.function_tailcalls += 1
        new_pos, registers, stack_offset = self.asm.find_free_registers_before(pos, 1)
        if len(registers):
            self.function_tailcalls_with_scratch += 1
        elif self.verbose:
            print('NO SCRATCH', pos, self.asm.lines[pos])
        return False

    def get_statistics(self) -> List[int]:
        return [self.function_begins, self.function_returns, self.function_tailcalls,
                self.function_begins_with_scratch, self.function_returns_with_scratch, self.function_tailcalls_with_scratch,
                self.function_begins_with_canaries, self.function_returns_with_canaries]

    def find_canary(self, pos, direction=1) -> bool:
        limit = -1
        while 0 < pos < len(self.asm.lines) and pos != limit:
            line = uncomment_r(self.asm.lines[pos]).rstrip()
            # is this the start of a new function?
            if line == '\t.cfi_startproc':
                return False
            if len(line) > 0 and line[0] != '.' and line[0] != '\t' and re.match(r'^\w+:$', line) and 'GCC_except_table' not in line:
                return False
            # must stay in the same basic block
            if line.startswith('\tret') or line.startswith('\tcall') and '__stack_chk_fail' not in line:
                return False
            if line.startswith('\tj') or line.startswith('.L'):
                limit = pos + direction * 20
            # is this an instruction?
            if line.startswith('\t') and not line.startswith('\t.'):
                if line.startswith('\tmovq\t%fs:40, ') or line.startswith('\txorq\t%fs:40, ') or '__stack_chk_fail' in line:
                    return True
            pos += direction
        return False



if __name__ == '__main__':
    test_asm = AssemblyFile('test_input.s')
    test_asm.rewriters.append(MemorySafeFunctionFilter(test_asm))
    test_asm.rewriters.append(ShadowStackRewriter(test_asm))
    #test_asm.rewriters.append(RipXoringRewriter(test_asm))
    test_asm.rewrite()
    for r in test_asm.rewriters:
        print('Stats for', r.__class__.__name__, r.get_statistics())
    test_asm.filename = 'test_input_processed.s'
    test_asm.save()
