# -*- coding: cp949 -*-
from pydbg import *
from pydbg.defines import *

import struct
import random

#사용자 정의 콜백 함수
def printf_randomizer(dbg):

    # ESP + 0x8 위치에 있는 counter DWORD 값을 읽는다.
    parameter_addr = dbg.context.Esp + 0x8
    counter = dbg.read_process_memory(parameter_addr,4)

    # read_process_memory는 패킹된 바이너리 문자열을 리턴한다.
    # 따라서 사용하기 전에 언팩을 수행해야 한다.
    counter = struct.unpack("L",counter)[0]
    print "Counter: %d" % int(counter)

    # 임의수를 만들고 바이너리 포멧으로 패킹
    random_counter = random.randint(1,100)
    random_counter = struct.pack("L", random_counter)[0]

    # 디버깅 대상 프로세스에 임의수를 써넣고 프로세스가 계속 실행되게 만든다.
    dbg.write_process_memory(parameter_addr, random_counter)

    return DBG_CONTINUE

# pydbg 클래스 인스턴스
dbg = pydbg()

# printf_loop.py 프로세스의 PID를 입력한다.
pid = raw_input("PID : ")

# 해당 프로세스에 디버거를 붙인다.
dbg.attach(int(pid))

# printf_randomizer 함수를 콜백함수로 등록하면서 브레이크 포인트 설정
printf_address = dbg.func_resolve("msvcrt","printf")
dbg.bp_set(printf_address, description="printf_address",
           handler=printf_randomizer)

#프로세스가 실행되게 한다.
dbg.run()
