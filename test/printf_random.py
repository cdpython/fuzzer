# -*- coding: cp949 -*-
from pydbg import *
from pydbg.defines import *

import struct
import random

#����� ���� �ݹ� �Լ�
def printf_randomizer(dbg):

    # ESP + 0x8 ��ġ�� �ִ� counter DWORD ���� �д´�.
    parameter_addr = dbg.context.Esp + 0x8
    counter = dbg.read_process_memory(parameter_addr,4)

    # read_process_memory�� ��ŷ�� ���̳ʸ� ���ڿ��� �����Ѵ�.
    # ���� ����ϱ� ���� ������ �����ؾ� �Ѵ�.
    counter = struct.unpack("L",counter)[0]
    print "Counter: %d" % int(counter)

    # ���Ǽ��� ����� ���̳ʸ� �������� ��ŷ
    random_counter = random.randint(1,100)
    random_counter = struct.pack("L", random_counter)[0]

    # ����� ��� ���μ����� ���Ǽ��� ��ְ� ���μ����� ��� ����ǰ� �����.
    dbg.write_process_memory(parameter_addr, random_counter)

    return DBG_CONTINUE

# pydbg Ŭ���� �ν��Ͻ�
dbg = pydbg()

# printf_loop.py ���μ����� PID�� �Է��Ѵ�.
pid = raw_input("PID : ")

# �ش� ���μ����� ����Ÿ� ���δ�.
dbg.attach(int(pid))

# printf_randomizer �Լ��� �ݹ��Լ��� ����ϸ鼭 �극��ũ ����Ʈ ����
printf_address = dbg.func_resolve("msvcrt","printf")
dbg.bp_set(printf_address, description="printf_address",
           handler=printf_randomizer)

#���μ����� ����ǰ� �Ѵ�.
dbg.run()
